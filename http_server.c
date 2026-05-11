/*
 * single_http_server.c
 *
 * 평문 HTTP 파일 전송 서버 (NVIDIA XLIO 성능 측정 사전 단계)
 *
 * 목적:
 *   - base-dir 아래의 대용량 파일(30G 등)을 sendfile()로 전송
 *   - "일반 실행" vs "LD_PRELOAD=libxlio.so 실행" 비교
 *   - 측정 스크립트(server_multicore_measure.sh) 완전 호환
 *
 * CLI:
 *   ./single_http_server <port> <mode> <cert.pem> <key.pem> <base-dir> <workers>
 *   - mode, cert.pem, key.pem: 호환성 위해 받되 무시
 *   - workers: 받되 단일 스레드로 동작
 *
 * 환경변수:
 *   SNDBUF         - SO_SNDBUF 값 (0이면 미설정, 기본: 커널 기본값)
 *   NOTSENT_LOWAT  - TCP_NOTSENT_LOWAT 값 (0이면 미설정)
 *
 * 컴파일:
 *   gcc -O2 -o single_http_server single_http_server.c
 *
 * 실행 예시 (직접):
 *   ./single_http_server 4613 plain dummy.pem dummy.pem /data 1
 *
 * 실행 예시 (측정 스크립트 경유):
 *   env SNDBUF=$((1024*1024)) NOTSENT_LOWAT=$((128*1024)) \
 *       SERVER_BIN=./single_http_server \
 *       ... 측정스크립트.sh
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/*  전역 상태                                                          */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t g_running = 1;
static char g_base_real[PATH_MAX];     /* base-dir의 realpath 결과 */

/* 환경변수에서 읽는 소켓 옵션 */
static int g_sndbuf        = 0;  /* SO_SNDBUF        (0 = 미설정) */
static int g_notsent_lowat = 0;  /* TCP_NOTSENT_LOWAT (0 = 미설정) */

/* ------------------------------------------------------------------ */
/*  시그널 핸들러                                                       */
/* ------------------------------------------------------------------ */
static void sig_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ------------------------------------------------------------------ */
/*  CLOCK_MONOTONIC_RAW 기준 나노초 반환                                */
/* ------------------------------------------------------------------ */
static inline long long now_ns_raw(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/*  URL decode (in-place)                                              */
/* ------------------------------------------------------------------ */
static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char *dst, const char *src)
{
    while (*src) {
        if (*src == '%' && src[1] && src[2]) {
            int hi = hex_val(src[1]);
            int lo = hex_val(src[2]);
            if (hi >= 0 && lo >= 0) {
                *dst++ = (char)((hi << 4) | lo);
                src += 3;
                continue;
            }
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

/* ------------------------------------------------------------------ */
/*  안전한 경로 구성: base-dir 바깥 접근 차단                            */
/* ------------------------------------------------------------------ */
static int safe_resolve(const char *requested, char *full_path)
{
    /* "../" 포함 여부 사전 검사 */
    if (strstr(requested, "..")) return -1;

    /* base-dir + "/" + requested 결합 */
    char joined[PATH_MAX];
    int n = snprintf(joined, sizeof(joined), "%s/%s", g_base_real, requested);
    if (n < 0 || (size_t)n >= sizeof(joined)) return -1;

    /* realpath로 정규화 */
    if (!realpath(joined, full_path)) return -1;

    /* base-dir 접두사 확인 */
    size_t baselen = strlen(g_base_real);
    if (strncmp(full_path, g_base_real, baselen) != 0) return -1;
    if (full_path[baselen] != '\0' && full_path[baselen] != '/') return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  HTTP 오류 응답 전송                                                 */
/* ------------------------------------------------------------------ */
static void send_error(int fd, int code, const char *reason)
{
    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s\n",
        code, reason, strlen(reason) + 1, reason);
    if (len > 0) {
        (void)send(fd, buf, (size_t)len, 0);
    }
}

/* ------------------------------------------------------------------ */
/*  요청 라인 파싱: "GET /path HTTP/1.x"에서 path 추출                  */
/* ------------------------------------------------------------------ */
static int parse_request_line(const char *line, char *path_out, size_t pathsz)
{
    if (strncasecmp(line, "GET ", 4) != 0) return -1;
    const char *p = line + 4;

    while (*p == ' ') p++;
    if (*p != '/') return -1;

    const char *end = p;
    while (*end && *end != ' ' && *end != '\r' && *end != '\n') end++;

    size_t uri_len = (size_t)(end - p);
    if (uri_len == 0 || uri_len >= pathsz) return -1;

    char uri[PATH_MAX];
    memcpy(uri, p, uri_len);
    uri[uri_len] = '\0';

    /* query string 제거 */
    char *q = strchr(uri, '?');
    if (q) *q = '\0';

    /* 선행 / 제거 */
    const char *clean = uri;
    while (*clean == '/') clean++;

    url_decode(path_out, clean);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  파일 본문 전송 (sendfile 우선, fallback: read+send)                 */
/* ------------------------------------------------------------------ */
static off_t transfer_file(int sock_fd, int file_fd, off_t file_size)
{
    off_t total_sent = 0;
    off_t offset = 0;

    while (total_sent < file_size) {
        off_t remaining = file_size - total_sent;
        size_t chunk = (remaining > 0x7FFFF000LL) ? 0x7FFFF000UL : (size_t)remaining;

        ssize_t sent = sendfile(sock_fd, file_fd, &offset, chunk);
        if (sent > 0) {
            total_sent += sent;
        } else if (sent == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            printf("FALLBACK fd=%d sendfile_errno=%d switching to read+send\n",
                   sock_fd, errno);
            fflush(stdout);
            goto fallback;
        }
    }
    return total_sent;

fallback:
    if (lseek(file_fd, offset, SEEK_SET) == (off_t)-1) return -1;

    {
        char buf[256 * 1024];
        while (total_sent < file_size) {
            off_t remaining = file_size - total_sent;
            size_t to_read = (remaining > (off_t)sizeof(buf)) ? sizeof(buf) : (size_t)remaining;

            ssize_t rd = read(file_fd, buf, to_read);
            if (rd <= 0) {
                if (rd == 0) break;
                if (errno == EINTR) continue;
                return -1;
            }

            size_t wr_off = 0;
            while (wr_off < (size_t)rd) {
                ssize_t wr = send(sock_fd, buf + wr_off, (size_t)rd - wr_off, 0);
                if (wr > 0) {
                    wr_off += (size_t)wr;
                } else {
                    if (errno == EINTR) continue;
                    return -1;
                }
            }
            total_sent += rd;
        }
    }
    return total_sent;
}

/* ------------------------------------------------------------------ */
/*  소켓 옵션 적용 (TCP_NODELAY, SO_SNDBUF, TCP_NOTSENT_LOWAT)        */
/* ------------------------------------------------------------------ */
static void apply_sock_opts(int fd)
{
    /* TCP_NODELAY */
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    /* SO_SNDBUF */
    if (g_sndbuf > 0) {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &g_sndbuf, sizeof(g_sndbuf)) == 0) {
            int actual = 0;
            socklen_t len = sizeof(actual);
            getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &actual, &len);
            printf("SOCKOPT fd=%d SO_SNDBUF requested=%d actual=%d\n",
                   fd, g_sndbuf, actual);
        } else {
            printf("SOCKOPT fd=%d SO_SNDBUF=%d FAILED errno=%d\n",
                   fd, g_sndbuf, errno);
        }
        fflush(stdout);
    }

    /* TCP_NOTSENT_LOWAT */
    if (g_notsent_lowat > 0) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT,
                       &g_notsent_lowat, sizeof(g_notsent_lowat)) == 0) {
            printf("SOCKOPT fd=%d TCP_NOTSENT_LOWAT=%d\n", fd, g_notsent_lowat);
        } else {
            printf("SOCKOPT fd=%d TCP_NOTSENT_LOWAT=%d FAILED errno=%d\n",
                   fd, g_notsent_lowat, errno);
        }
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------ */
/*  클라이언트 요청 처리                                                */
/* ------------------------------------------------------------------ */
static void handle_client(int client_fd, struct sockaddr_in *addr)
{
    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, addr_str, sizeof(addr_str));

    /* 소켓 옵션 적용 */
    apply_sock_opts(client_fd);

    /* 요청 헤더 읽기 (최대 8KB) */
    char reqbuf[8192];
    ssize_t total_read = 0;
    int got_headers = 0;

    while (total_read < (ssize_t)(sizeof(reqbuf) - 1)) {
        ssize_t rd = recv(client_fd, reqbuf + total_read,
                          sizeof(reqbuf) - 1 - (size_t)total_read, 0);
        if (rd <= 0) break;
        total_read += rd;
        reqbuf[total_read] = '\0';
        if (strstr(reqbuf, "\r\n\r\n") || strstr(reqbuf, "\n\n")) {
            got_headers = 1;
            break;
        }
    }

    if (!got_headers && total_read <= 0) {
        close(client_fd);
        return;
    }
    reqbuf[total_read] = '\0';

    /* 요청 라인 파싱 */
    char rel_path[PATH_MAX];
    if (parse_request_line(reqbuf, rel_path, sizeof(rel_path)) != 0) {
        send_error(client_fd, 400, "Bad Request");
        close(client_fd);
        return;
    }

    if (rel_path[0] == '\0') {
        send_error(client_fd, 403, "Forbidden");
        close(client_fd);
        return;
    }

    /* 안전한 경로 해석 */
    char full_path[PATH_MAX];
    if (safe_resolve(rel_path, full_path) != 0) {
        send_error(client_fd, 404, "Not Found");
        close(client_fd);
        return;
    }

    /* 파일 열기 */
    int file_fd = open(full_path, O_RDONLY);
    if (file_fd < 0) {
        send_error(client_fd, 404, "Not Found");
        close(client_fd);
        return;
    }

    struct stat st;
    if (fstat(file_fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        send_error(client_fd, 404, "Not Found");
        close(file_fd);
        close(client_fd);
        return;
    }
    off_t file_size = st.st_size;

    /* 파일명 추출 */
    const char *filename = strrchr(rel_path, '/');
    filename = filename ? filename + 1 : rel_path;

    /* 디버깅 로그: REQUEST */
    printf("REQUEST fd=%d path=\"%s\" size=%lld\n",
           client_fd, rel_path, (long long)file_size);
    fflush(stdout);

    /* HTTP 200 응답 헤더 */
    char hdrbuf[1024];
    int hdrlen = snprintf(hdrbuf, sizeof(hdrbuf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lld\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Connection: close\r\n"
        "\r\n",
        (long long)file_size, filename);

    /* 헤더 전송 */
    {
        size_t off = 0;
        while (off < (size_t)hdrlen) {
            ssize_t wr = send(client_fd, hdrbuf + off, (size_t)hdrlen - off, 0);
            if (wr > 0) {
                off += (size_t)wr;
            } else {
                if (errno == EINTR) continue;
                fprintf(stderr, "ERROR: header send failed fd=%d errno=%d\n",
                        client_fd, errno);
                close(file_fd);
                close(client_fd);
                return;
            }
        }
    }

    /* ============================================================== */
    /*  MEASURE_BEGIN: 파일 본문 전송 직전                               */
    /* ============================================================== */
    long long t_begin = now_ns_raw();
    printf("MEASURE_BEGIN fd=%d path=\"%s\" size=%lld t_ns=%lld\n",
           client_fd, rel_path, (long long)file_size, t_begin);
    fflush(stdout);

    /* 파일 본문 전송 */
    off_t bytes_sent = transfer_file(client_fd, file_fd, file_size);

    /* ============================================================== */
    /*  MEASURE_END: 파일 본문 전송 완료 직후                            */
    /* ============================================================== */
    long long t_end = now_ns_raw();
    printf("MEASURE_END fd=%d path=\"%s\" bytes=%lld t_ns=%lld\n",
           client_fd, rel_path, (long long)bytes_sent, t_end);
    fflush(stdout);

    /* 디버깅 로그: COMPLETE */
    printf("COMPLETE fd=%d path=\"%s\" bytes=%lld\n",
           client_fd, rel_path, (long long)bytes_sent);
    fflush(stdout);

    close(file_fd);
    close(client_fd);
}

/* ------------------------------------------------------------------ */
/*  환경변수에서 정수 읽기                                              */
/* ------------------------------------------------------------------ */
static int env_int(const char *name, int defval)
{
    const char *v = getenv(name);
    if (!v || !*v) return defval;
    char *end;
    long val = strtol(v, &end, 10);
    if (*end != '\0') return defval;
    return (int)val;
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc < 7) {
        fprintf(stderr,
            "Usage: %s <port> <mode> <cert.pem> <key.pem> <base-dir> <workers>\n"
            "\n"
            "  port      - listen port\n"
            "  mode      - ignored (compatibility)\n"
            "  cert.pem  - ignored (compatibility)\n"
            "  key.pem   - ignored (compatibility)\n"
            "  base-dir  - directory containing files to serve\n"
            "  workers   - ignored (single-thread)\n"
            "\n"
            "Environment:\n"
            "  SNDBUF        - SO_SNDBUF value (0=kernel default)\n"
            "  NOTSENT_LOWAT - TCP_NOTSENT_LOWAT value (0=disabled)\n",
            argv[0]);
        return 1;
    }

    int port         = atoi(argv[1]);
    /* argv[2] mode     - 무시 */
    /* argv[3] cert.pem - 무시 */
    /* argv[4] key.pem  - 무시 */
    const char *base = argv[5];
    /* argv[6] workers  - 무시 */

    /* stdout line-buffered */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* 환경변수 읽기 */
    g_sndbuf        = env_int("SNDBUF", 0);
    g_notsent_lowat = env_int("NOTSENT_LOWAT", 0);

    /* base-dir 정규화 */
    if (!realpath(base, g_base_real)) {
        fprintf(stderr, "ERROR: cannot resolve base-dir '%s': %s\n",
                base, strerror(errno));
        return 1;
    }

    printf("CONFIG port=%d base-dir=\"%s\" SNDBUF=%d NOTSENT_LOWAT=%d\n",
           port, g_base_real, g_sndbuf, g_notsent_lowat);
    fflush(stdout);

    /* 시그널 설정 */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* listen 소켓 */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port        = htons((uint16_t)port);

    if (bind(listen_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("LISTEN port=%d fd=%d\n", port, listen_fd);
    fflush(stdout);

    /* 메인 루프 */
    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, addr_str, sizeof(addr_str));
        printf("ACCEPT fd=%d from=%s:%d\n",
               client_fd, addr_str, ntohs(client_addr.sin_port));
        fflush(stdout);

        handle_client(client_fd, &client_addr);
    }

    printf("SHUTDOWN\n");
    fflush(stdout);
    close(listen_fd);
    return 0;
}
