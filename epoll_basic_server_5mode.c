#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#define MAX_WORKERS     128
#define MAX_EVENTS      256
#define REQ_BUFSZ       8192
#define HDR_BUFSZ       1024
#define FILE_CHUNK      (256 * 1024)
#define LISTEN_BACKLOG  4096

#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TLS_TX
#define TLS_TX 1
#endif

/* ====================================================================
 * 5-Mode 서버
 *   HTTP        : 평문 (TLS 없음)
 *   OPENSSL     : OpenSSL SW 암호화 (SSL_write)
 *   SWKTLS      : 커널 kTLS, NIC offload OFF (커널이 SW로 암호화)
 *   HWKTLS      : 커널 kTLS, NIC offload ON  (NIC가 HW로 암호화)
 *   XLIO_HWKTLS : XLIO 유저공간 스택 + NIC HW offload (kernel bypass)
 *
 *  주의: SWKTLS 와 HWKTLS 는 서버 코드 관점에서 동일하다.
 *        실제 SW/HW 결정은 ethtool -K <iface> tls-hw-tx-offload on/off 로 한다.
 *        스크립트가 모드별로 ethtool 을 설정해야 한다.
 *        XLIO_HWKTLS 는 LD_PRELOAD=libxlio.so 가 켜져 있어야 한다.
 * ==================================================================== */

typedef enum {
    MODE_HTTP        = 0,
    MODE_OPENSSL     = 1,
    MODE_SWKTLS      = 2,
    MODE_HWKTLS      = 3,
    MODE_XLIO_HWKTLS = 4
} tls_mode_t;

static const char *mode_name(tls_mode_t m) {
    switch (m) {
        case MODE_HTTP:        return "HTTP";
        case MODE_OPENSSL:     return "OPENSSL";
        case MODE_SWKTLS:      return "SWKTLS";
        case MODE_HWKTLS:      return "HWKTLS";
        case MODE_XLIO_HWKTLS: return "XLIO_HWKTLS";
    }
    return "?";
}

static bool mode_uses_ssl(tls_mode_t m) {
    return m != MODE_HTTP;
}

static bool mode_enables_ktls(tls_mode_t m) {
    return (m == MODE_SWKTLS || m == MODE_HWKTLS || m == MODE_XLIO_HWKTLS);
}

typedef enum {
    ST_HANDSHAKE = 0,
    ST_READ_REQ,
    ST_SEND_HDR,
    ST_SEND_FILE,
    ST_CLOSING
} conn_state_t;

typedef struct {
    int        port;
    tls_mode_t mode;
    char       cert[PATH_MAX];
    char       key[PATH_MAX];
    char       base_dir[PATH_MAX];
    int        workers;
    bool       xlio_detected;
    bool       allow_sw_fallback;
    int        verbose;
    int        sndbuf;        /* SO_SNDBUF, 0이면 미적용 */
    int        notsent_lowat; /* TCP_NOTSENT_LOWAT, 0이면 미적용 */
} server_cfg_t;

typedef struct conn {
    int          fd;
    SSL         *ssl;          /* HTTP 모드면 NULL */
    conn_state_t st;
    bool         use_raw_send; /* true: send()/read() 직접 사용 (HTTP 또는 kTLS active) */
    bool         ktls_active;  /* kTLS TX 활성 여부 (SWKTLS/HWKTLS/XLIO 에서 의미) */
    bool         use_sendfile; /* true: SWKTLS/HWKTLS에서 sendfile() 경로 사용 */
    bool         measure_begun;

    char   req[REQ_BUFSZ];
    size_t req_len;

    char   relpath[NAME_MAX + 1];

    int    file_fd;
    off_t  file_size;
    off_t  file_sent;          /* sendfile 경로용 누적 송신량 */

    char   hdr[HDR_BUFSZ];
    size_t hdr_len;
    size_t hdr_off;

    unsigned char *buf;
    size_t         buf_cap;
    size_t         buf_len;
    size_t         buf_off;
} conn_t;

typedef struct {
    int                 id;
    int                 cpu;
    int                 epfd;
    int                 listen_fd;
    SSL_CTX            *ctx;     /* HTTP 모드면 NULL */
    const server_cfg_t *cfg;
    pthread_t           tid;
} worker_t;

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static uint64_t now_ns_raw(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void die_perror(const char *m) { perror(m); exit(EXIT_FAILURE); }
static void die_ssl(const char *m) { fprintf(stderr,"FATAL: %s\n",m); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int pick_nth_allowed_cpu(int n) {
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        long c = sysconf(_SC_NPROCESSORS_ONLN);
        return (c > 0) ? (n % (int)c) : 0;
    }
    int cpus[CPU_SETSIZE]; int cnt = 0;
    for (int i = 0; i < CPU_SETSIZE; ++i)
        if (CPU_ISSET(i, &allowed)) cpus[cnt++] = i;
    return cnt ? cpus[n % cnt] : 0;
}

static void pin_to_cpu(int cpu) {
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
        perror("pthread_setaffinity_np");
}

/* ================ XLIO / kernel-tls 환경 감지 ================ */

static bool detect_xlio(void) {
    const char *preload = getenv("LD_PRELOAD");
    if (preload && (strstr(preload, "libxlio") || strstr(preload, "xlio"))) return true;
    if (dlsym(RTLD_DEFAULT, "xlio_socket")) return true;
    return false;
}

static bool check_kernel_tls_module(void) {
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[256]; bool found = false;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "tls ", 4) == 0) { found = true; break; }
    fclose(f);
    return found;
}

/* ================ args ================ */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <port> <MODE> <cert.pem> <key.pem> <base_dir> [workers]\n"
        "\n"
        "Modes:\n"
        "  HTTP         - plaintext HTTP, no TLS\n"
        "  OPENSSL      - OpenSSL SW encryption (SSL_write)\n"
        "  SWKTLS       - kernel kTLS, NIC offload OFF\n"
        "                 (set: ethtool -K <iface> tls-hw-tx-offload off)\n"
        "  HWKTLS       - kernel kTLS, NIC offload ON\n"
        "                 (set: ethtool -K <iface> tls-hw-tx-offload on)\n"
        "  XLIO_HWKTLS  - XLIO + NIC HW offload, requires LD_PRELOAD=libxlio.so\n"
        "\n"
        "Note: For HTTP mode, cert/key are ignored but must be provided as placeholders.\n"
        "\n"
        "Env vars:\n"
        "  VERBOSE=0..3          (default: 1)\n"
        "  ALLOW_SW_FALLBACK=0|1 (default: 0)  fallback to SSL_write if kTLS fails\n",
        prog);
    exit(EXIT_FAILURE);
}

static tls_mode_t parse_mode(const char *s) {
    if (!strcasecmp(s, "HTTP"))        return MODE_HTTP;
    if (!strcasecmp(s, "OPENSSL"))     return MODE_OPENSSL;
    if (!strcasecmp(s, "SWKTLS"))      return MODE_SWKTLS;
    if (!strcasecmp(s, "HWKTLS"))      return MODE_HWKTLS;
    if (!strcasecmp(s, "XLIO_HWKTLS")) return MODE_XLIO_HWKTLS;
    if (!strcasecmp(s, "XLIO"))        return MODE_XLIO_HWKTLS; /* alias */

    fprintf(stderr, "Invalid mode: %s\n", s);
    fprintf(stderr, "Valid: HTTP | OPENSSL | SWKTLS | HWKTLS | XLIO_HWKTLS\n");
    exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv, server_cfg_t *cfg) {
    if (argc != 6 && argc != 7) usage(argv[0]);
    memset(cfg, 0, sizeof(*cfg));
    cfg->port    = atoi(argv[1]);
    cfg->mode    = parse_mode(argv[2]);
    cfg->workers = (argc == 7) ? atoi(argv[6]) : 1;
    if (cfg->port <= 0 || cfg->port > 65535) usage(argv[0]);
    if (cfg->workers <= 0) cfg->workers = 1;
    if (cfg->workers > MAX_WORKERS) cfg->workers = MAX_WORKERS;

    snprintf(cfg->cert, sizeof(cfg->cert), "%s", argv[3]);
    snprintf(cfg->key,  sizeof(cfg->key),  "%s", argv[4]);
    snprintf(cfg->base_dir, sizeof(cfg->base_dir), "%s", argv[5]);

    const char *v  = getenv("VERBOSE");          cfg->verbose = v ? atoi(v) : 1;
    const char *fb = getenv("ALLOW_SW_FALLBACK"); cfg->allow_sw_fallback = (fb && atoi(fb) == 1);
    cfg->xlio_detected = detect_xlio();

    /* 소켓 튜닝 환경변수 (XLIO 미감지 시에만 적용됨) */
    const char *sb  = getenv("SNDBUF");         cfg->sndbuf        = sb ? atoi(sb) : 0;
    const char *nsl = getenv("NOTSENT_LOWAT");  cfg->notsent_lowat = nsl ? atoi(nsl) : 0;

    /* XLIO_HWKTLS 모드인데 LD_PRELOAD 없으면 즉시 에러 */
    if (cfg->mode == MODE_XLIO_HWKTLS && !cfg->xlio_detected) {
        fprintf(stderr, "FATAL: MODE=XLIO_HWKTLS but XLIO not preloaded.\n"
                        "       Run with: LD_PRELOAD=libxlio.so ...\n");
        exit(EXIT_FAILURE);
    }
}

/* ================ SSL_CTX ================ */

static SSL_CTX *make_ctx(const server_cfg_t *cfg) {
    if (!mode_uses_ssl(cfg->mode)) return NULL;

    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die_ssl("SSL_CTX_new");

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) die_ssl("min_proto");
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) != 1) die_ssl("max_proto");
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256") != 1) die_ssl("cipher_list");

#ifdef SSL_OP_ENABLE_KTLS
    if (mode_enables_ktls(cfg->mode)) {
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        if (cfg->verbose >= 1) {
            fprintf(stdout, "INIT SSL_OP_ENABLE_KTLS set on SSL_CTX (mode=%s)\n",
                    mode_name(cfg->mode));
            fflush(stdout);
        }
    }
#else
    if (mode_enables_ktls(cfg->mode)) {
        fprintf(stderr, "This OpenSSL build does not expose SSL_OP_ENABLE_KTLS\n");
        exit(EXIT_FAILURE);
    }
#endif

    if (SSL_CTX_use_certificate_file(ctx, cfg->cert, SSL_FILETYPE_PEM) != 1) die_ssl("cert");
    if (SSL_CTX_use_PrivateKey_file (ctx, cfg->key , SSL_FILETYPE_PEM) != 1) die_ssl("key");
    if (SSL_CTX_check_private_key(ctx) != 1) die_ssl("check_private_key");
    return ctx;
}

static int make_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die_perror("socket");
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die_perror("bind");
    if (listen(fd, LISTEN_BACKLOG) < 0) die_perror("listen");
    if (set_nonblock(fd) < 0) die_perror("set_nonblock(listen)");
    return fd;
}

/* ================ http parsing helpers (기존과 동일) ================ */

static bool req_line_complete(const char *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; ++i)
        if (buf[i] == '\r' && buf[i + 1] == '\n') return true;
    for (size_t i = 0; i < len; ++i)
        if (buf[i] == '\n') return true;
    return false;
}

static size_t url_decode(char *s) {
    char *src = s, *dst = s;
    while (*src) {
        if (src[0] == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = { src[1], src[2], 0 };
            *dst++ = (char)strtol(hex, NULL, 16); src += 3;
        } else if (*src == '+') { *dst++ = ' '; src++; }
        else *dst++ = *src++;
    }
    *dst = '\0';
    return (size_t)(dst - s);
}

static int safe_join_under_base(const char *base, const char *name, char out[PATH_MAX]) {
    char realb[PATH_MAX]; if (!realpath(base, realb)) return -1;
    char cand[PATH_MAX];
    if (snprintf(cand, sizeof(cand), "%s/%s", base, name) >= (int)sizeof(cand)) return -1;
    char *realc = realpath(cand, NULL); if (!realc) return -1;
    size_t bl = strlen(realb);
    int ok = (strncmp(realb, realc, bl) == 0) && (realc[bl] == '/' || realc[bl] == '\0');
    if (ok) { strncpy(out, realc, PATH_MAX - 1); out[PATH_MAX - 1] = '\0'; }
    free(realc);
    return ok ? 0 : -1;
}

static void conn_free(conn_t *c) {
    if (!c) return;
    if (c->file_fd >= 0) close(c->file_fd);
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); }
    if (c->fd >= 0) close(c->fd);
    free(c->buf);
    free(c);
}

static int conn_ctl(int epfd, int op, conn_t *c, uint32_t events) {
    struct epoll_event ev; memset(&ev, 0, sizeof(ev));
    ev.events = events | EPOLLET | EPOLLRDHUP; ev.data.ptr = c;
    return epoll_ctl(epfd, op, c->fd, &ev);
}
static int arm_conn(int epfd, conn_t *c, uint32_t events) { return conn_ctl(epfd, EPOLL_CTL_MOD, c, events); }
static int add_conn(int epfd, conn_t *c, uint32_t events) { return conn_ctl(epfd, EPOLL_CTL_ADD, c, events); }

static int ssl_is_ktls_send_active(SSL *ssl) {
    BIO *wbio = SSL_get_wbio(ssl);
    if (!wbio) return 0;
    long ktls = BIO_ctrl(wbio, BIO_CTRL_GET_KTLS_SEND, 0, NULL);
    return (ktls > 0) ? 1 : 0;
}

/* ================ raw / SSL IO 추상화 ================ */

static ssize_t raw_read_nb(int fd, void *buf, size_t cap) {
    for (;;) {
        ssize_t n = recv(fd, buf, cap, 0);
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        return -1;
    }
}

static ssize_t raw_send_nb(int fd, const void *buf, size_t len) {
    for (;;) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        return -1;
    }
}

static ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t cap, int *want) {
    *want = 0;
    int n = SSL_read(ssl, buf, (int)cap);
    if (n > 0) return n;
    int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_WANT_READ)  { *want = EPOLLIN;  errno = EAGAIN; return -1; }
    if (e == SSL_ERROR_WANT_WRITE) { *want = EPOLLOUT; errno = EAGAIN; return -1; }
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    errno = EIO; return -1;
}

static ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len, int *want) {
    *want = 0;
    int n = SSL_write(ssl, buf, (int)len);
    if (n > 0) return n;
    int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_WANT_READ)  { *want = EPOLLIN;  errno = EAGAIN; return -1; }
    if (e == SSL_ERROR_WANT_WRITE) { *want = EPOLLOUT; errno = EAGAIN; return -1; }
    errno = EIO; return -1;
}

/* 통합 write: HTTP/raw/SSL 자동 분기.
 * read 측은 모드별 분기가 약간 달라서 handle_read_req 안에서 직접 처리한다. */
static int send_app_data(conn_t *c, const void *buf, size_t len, int *want) {
    *want = 0;
    if (c->use_raw_send) {
        ssize_t n = raw_send_nb(c->fd, buf, len);
        if (n > 0) return (int)n;
        if (n == 0) return -1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { *want = EPOLLOUT; return 0; }
        return -1;
    }
    ssize_t n = ssl_write_nb(c->ssl, buf, len, want);
    if (n > 0) return (int)n;
    if (n == 0) return -1;
    if (errno == EAGAIN) return 0;
    return -1;
}

/* ================ flush_hdr / flush_file ================ */

static int flush_hdr(conn_t *c, int epfd) {
    while (c->hdr_off < c->hdr_len) {
        int want = 0;
        int n = send_app_data(c, c->hdr + c->hdr_off, c->hdr_len - c->hdr_off, &want);
        if (n > 0) { c->hdr_off += (size_t)n; continue; }
        if (n == 0) {
            if (arm_conn(epfd, c, want ? (uint32_t)want : EPOLLOUT) < 0) return -1;
            return 0;
        }
        return -1;
    }
    return 1;
}

static int refill_buf(conn_t *c) {
    if (!c->buf) {
        c->buf = (unsigned char *)malloc(FILE_CHUNK);
        if (!c->buf) return -1;
        c->buf_cap = FILE_CHUNK;
    }
    c->buf_off = 0; c->buf_len = 0;
    for (;;) {
        ssize_t n = read(c->file_fd, c->buf, c->buf_cap);
        if (n > 0)  { c->buf_len = (size_t)n; return 1; }
        if (n == 0) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
}

/* sendfile 경로 (SWKTLS/HWKTLS 전용)
 *
 * kTLS가 활성화된 소켓에 sendfile()을 호출하면:
 *  - SWKTLS: 커널이 페이지 캐시 → kTLS SW 암호화 → TCP 송신 (유저공간 복사 없음)
 *  - HWKTLS: 커널이 페이지 캐시 → NIC TLS HW 암호화 → 송신 (zero-copy + HW)
 *
 * OPENSSL/XLIO_HWKTLS 에서는 사용하지 않는다.
 *  - OPENSSL: SSL_write가 유저공간 암호화를 해야 함
 *  - XLIO   : XLIO 소켓 fd는 유저공간 가짜 fd라 커널 sendfile() 호환 안 됨
 */
static int flush_file_sendfile(conn_t *c, int epfd) {
    while (c->file_sent < c->file_size) {
        size_t remain = (size_t)(c->file_size - c->file_sent);
        size_t chunk  = remain > FILE_CHUNK ? FILE_CHUNK : remain;
        /* offset=NULL: file_fd의 현재 offset 사용 (sendfile이 자동 갱신) */
        ssize_t n = sendfile(c->fd, c->file_fd, NULL, chunk);
        if (n > 0) {
            c->file_sent += n;
            continue;
        }
        if (n == 0) {
            /* 파일이 fsize보다 짧음 — 정상 종료로 간주 */
            return 1;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (arm_conn(epfd, c, EPOLLOUT) < 0) return -1;
            return 0;
        }
        return -1;
    }
    return 1;
}

static int flush_file(conn_t *c, int epfd) {
    for (;;) {
        if (c->buf_off == c->buf_len) {
            int r = refill_buf(c);
            if (r < 0) return -1;
            if (r == 0) return 1;
        }
        while (c->buf_off < c->buf_len) {
            int want = 0;
            int n = send_app_data(c, c->buf + c->buf_off, c->buf_len - c->buf_off, &want);
            if (n > 0) { c->buf_off += (size_t)n; continue; }
            if (n == 0) {
                if (arm_conn(epfd, c, want ? (uint32_t)want : EPOLLOUT) < 0) return -1;
                return 0;
            }
            return -1;
        }
    }
}

static int build_simple_response(conn_t *c, int code, const char *reason, const char *body) {
    int n = snprintf(c->hdr, sizeof(c->hdr),
                     "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     code, reason, strlen(body), body);
    if (n <= 0 || n >= (int)sizeof(c->hdr)) return -1;
    c->hdr_len = (size_t)n; c->hdr_off = 0;
    return 0;
}

static int build_file_response(conn_t *c, const server_cfg_t *cfg) {
    char full[PATH_MAX];
    if (safe_join_under_base(cfg->base_dir, c->relpath, full) < 0) return -1;
    c->file_fd = open(full, O_RDONLY | O_CLOEXEC);
    if (c->file_fd < 0) return -1;
    struct stat st;
    if (fstat(c->file_fd, &st) < 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;
    c->file_size = st.st_size;
    int n = snprintf(c->hdr, sizeof(c->hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                     "Content-Length: %lld\r\nConnection: close\r\n\r\n",
                     (long long)c->file_size);
    if (n <= 0 || n >= (int)sizeof(c->hdr)) return -1;
    c->hdr_len = (size_t)n; c->hdr_off = 0;
    return 0;
}

static int parse_request_line(conn_t *c) {
    char method[16] = {0}, target[PATH_MAX] = {0}, version[32] = {0};
    if (sscanf(c->req, "%15s %4095s %31s", method, target, version) != 3) return -1;
    if (strcmp(method, "GET") != 0) return -1;
    if (strncmp(version, "HTTP/1.1", 8) != 0 && strncmp(version, "HTTP/1.0", 8) != 0) return -1;
    if (target[0] != '/') return -1;
    const char *p = target + 1;
    while (*p == '/') p++;
    if (*p == '\0') return -1;
    size_t plen = strcspn(p, "?");
    if (plen == 0 || plen > NAME_MAX) return -1;
    memcpy(c->relpath, p, plen); c->relpath[plen] = '\0';
    url_decode(c->relpath);
    if (strstr(c->relpath, "..") || strchr(c->relpath, '\\')) return -1;
    return 0;
}

/* ================ handshake ================ */

static void handle_handshake(worker_t *w, conn_t *c) {
    /* HTTP 모드: 핸드셰이크 자체가 없음 — 곧장 READ_REQ */
    if (w->cfg->mode == MODE_HTTP) {
        c->use_raw_send = true;
        c->ktls_active  = false;
        c->use_sendfile = false;  /* HTTP는 sendfile 안 씀 (간단성 우선) */
        fprintf(stdout, "HANDSHAKE_OK fd=%d mode=HTTP (no TLS)\n", c->fd);
        fflush(stdout);
        c->st = ST_READ_REQ;
        if (arm_conn(w->epfd, c, EPOLLIN) < 0) c->st = ST_CLOSING;
        return;
    }

    int r = SSL_accept(c->ssl);

    if (r == 1) {
        bool want_ktls = mode_enables_ktls(w->cfg->mode);

        if (want_ktls) {
            c->ktls_active = ssl_is_ktls_send_active(c->ssl) ? true : false;

            if (w->cfg->verbose >= 2) {
                fprintf(stdout, "DIAG handshake_done fd=%d mode=%s "
                        "BIO_get_ktls_send=%d xlio=%d\n",
                        c->fd, mode_name(w->cfg->mode),
                        c->ktls_active ? 1 : 0, w->cfg->xlio_detected ? 1 : 0);
                fflush(stdout);
            }

            if (!c->ktls_active) {
                if (w->cfg->allow_sw_fallback) {
                    fprintf(stdout, "FALLBACK fd=%d mode=%s -> OPENSSL_SW (kTLS inactive)\n",
                            c->fd, mode_name(w->cfg->mode));
                    fflush(stdout);
                    c->use_raw_send = false;
                } else {
                    fprintf(stdout, "ERROR ktls_not_active fd=%d mode=%s — "
                            "check: modprobe tls / ethtool tls-hw-tx-offload / "
                            "OpenSSL build (enable-ktls). Set ALLOW_SW_FALLBACK=1 to bypass.\n",
                            c->fd, mode_name(w->cfg->mode));
                    fflush(stdout);
                    c->st = ST_CLOSING;
                    return;
                }
            } else {
                /* kTLS 켜졌으면 raw send() 가 곧 암호화된 record 를 보냄 */
                c->use_raw_send = true;

                /* SWKTLS / HWKTLS 에선 sendfile() 사용
                 * XLIO_HWKTLS 는 유저공간 fd라 커널 sendfile() 호환 안 됨 → 제외 */
                if (w->cfg->mode == MODE_SWKTLS || w->cfg->mode == MODE_HWKTLS) {
                    c->use_sendfile = true;
                }
            }
        } else {
            /* OPENSSL 모드 */
            c->ktls_active  = false;
            c->use_raw_send = false;
            c->use_sendfile = false;
        }

        fprintf(stdout, "HANDSHAKE_OK fd=%d mode=%s ktls_tx=%d xlio=%d use_raw_send=%d use_sendfile=%d\n",
                c->fd, mode_name(w->cfg->mode),
                c->ktls_active ? 1 : 0,
                w->cfg->xlio_detected ? 1 : 0,
                c->use_raw_send ? 1 : 0,
                c->use_sendfile ? 1 : 0);
        fflush(stdout);

        c->st = ST_READ_REQ;
        if (arm_conn(w->epfd, c, EPOLLIN) < 0) c->st = ST_CLOSING;
        return;
    }

    int e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ)  { if (arm_conn(w->epfd, c, EPOLLIN)  < 0) c->st = ST_CLOSING; return; }
    if (e == SSL_ERROR_WANT_WRITE) { if (arm_conn(w->epfd, c, EPOLLOUT) < 0) c->st = ST_CLOSING; return; }

    fprintf(stdout, "ERROR handshake fd=%d ssl_error=%d\n", c->fd, e);
    ERR_print_errors_fp(stdout); fflush(stdout);
    c->st = ST_CLOSING;
}

/* ================ read_req / send_hdr / send_file ================ */

static void handle_read_req(worker_t *w, conn_t *c) {
    /* HTTP 모드 또는 kTLS 모드에선 raw recv, OpenSSL 모드에선 SSL_read.
     * HTTP 모드라도 read 는 어쨌든 들어오는 평문 GET 요청을 받는다.
     * kTLS TX 만 활성이고 RX 는 SSL 가 처리하는 경우(흔함)도 있는데,
     * 현재 코드에선 RX 에 대해서도 raw send 플래그 기준으로 분기.
     * 실제로 모드별 RX 측 처리는 다음과 같다:
     *   HTTP            : raw read
     *   OPENSSL         : SSL_read
     *   SWKTLS/HWKTLS   : SSL_read (RX 는 OpenSSL 이 처리; kTLS RX 는 별도 활성화 필요)
     *   XLIO_HWKTLS     : SSL_read (XLIO 가 내부에서 처리)
     * 따라서 read 측은 use_raw_send 가 아니라 mode 로 분기한다. */

    bool use_raw_read = (w->cfg->mode == MODE_HTTP);

    for (;;) {
        int want = 0;
        ssize_t n;

        if (use_raw_read) {
            n = raw_read_nb(c->fd, c->req + c->req_len, sizeof(c->req) - 1 - c->req_len);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { want = EPOLLIN; errno = EAGAIN; }
        } else {
            n = ssl_read_nb(c->ssl, c->req + c->req_len, sizeof(c->req) - 1 - c->req_len, &want);
        }

        if (n > 0) {
            c->req_len += (size_t)n;
            c->req[c->req_len] = '\0';
        } else if (n == 0) {
            c->st = ST_CLOSING; return;
        } else {
            if (errno == EAGAIN) {
                if (arm_conn(w->epfd, c, want ? (uint32_t)want : EPOLLIN) < 0) c->st = ST_CLOSING;
            } else {
                if (w->cfg->verbose >= 1) {
                    fprintf(stdout, "ERROR read fd=%d errno=%d\n", c->fd, errno);
                    fflush(stdout);
                }
                c->st = ST_CLOSING;
            }
            return;
        }

        if (!req_line_complete(c->req, c->req_len)) {
            if (c->req_len >= sizeof(c->req) - 1) {
                if (build_simple_response(c, 400, "Bad Request", "bad request\n") < 0) { c->st = ST_CLOSING; return; }
                c->st = ST_SEND_HDR;
            } else continue;
        } else {
            if (parse_request_line(c) < 0) {
                if (build_simple_response(c, 404, "Not Found", "not found\n") < 0) { c->st = ST_CLOSING; return; }
                c->st = ST_SEND_HDR;
            } else if (build_file_response(c, w->cfg) < 0) {
                if (build_simple_response(c, 404, "Not Found", "not found\n") < 0) { c->st = ST_CLOSING; return; }
                c->st = ST_SEND_HDR;
            } else {
                fprintf(stdout, "REQUEST fd=%d path=\"%s\" size=%lld\n",
                        c->fd, c->relpath, (long long)c->file_size);
                fflush(stdout);
                c->st = ST_SEND_HDR;
            }
        }
        return;
    }
}

static void handle_send_hdr(worker_t *w, conn_t *c) {
    int r = flush_hdr(c, w->epfd);
    if (r < 0)      { fprintf(stdout, "ERROR hdr fd=%d\n", c->fd); fflush(stdout); c->st = ST_CLOSING; }
    else if (r == 1) c->st = (c->file_fd >= 0) ? ST_SEND_FILE : ST_CLOSING;
}

static void handle_send_file(worker_t *w, conn_t *c) {
    if (!c->measure_begun) {
        fprintf(stdout, "MEASURE_BEGIN fd=%d path=\"%s\" size=%lld t_ns=%" PRIu64 " path_kind=%s\n",
                c->fd, c->relpath, (long long)c->file_size, now_ns_raw(),
                c->use_sendfile ? "sendfile" : "read+send");
        fflush(stdout);
        c->measure_begun = true;
    }
    int r = c->use_sendfile ? flush_file_sendfile(c, w->epfd)
                            : flush_file         (c, w->epfd);
    if (r < 0) { fprintf(stdout, "ERROR body fd=%d\n", c->fd); fflush(stdout); c->st = ST_CLOSING; }
    else if (r == 1) {
        fprintf(stdout, "MEASURE_END fd=%d path=\"%s\" bytes=%lld t_ns=%" PRIu64 "\n",
                c->fd, c->relpath, (long long)c->file_size, now_ns_raw());
        fprintf(stdout, "COMPLETE fd=%d path=\"%s\" bytes=%lld\n",
                c->fd, c->relpath, (long long)c->file_size);
        fflush(stdout);
        c->st = ST_CLOSING;
    }
}

static void handle_conn_event(worker_t *w, conn_t *c, uint32_t events) {
    if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) c->st = ST_CLOSING;

    while (c->st != ST_CLOSING) {
        switch (c->st) {
            case ST_HANDSHAKE: handle_handshake(w, c); if (c->st == ST_READ_REQ) continue; return;
            case ST_READ_REQ:  handle_read_req (w, c); if (c->st == ST_SEND_HDR)  continue; return;
            case ST_SEND_HDR:  handle_send_hdr (w, c); if (c->st == ST_SEND_FILE) continue; return;
            case ST_SEND_FILE: handle_send_file(w, c); return;
            default: break;
        }
    }
    epoll_ctl(w->epfd, EPOLL_CTL_DEL, c->fd, NULL);
    conn_free(c);
}

/* ================ accept ================ */

static void accept_loop(worker_t *w) {
    for (;;) {
        struct sockaddr_in peer; socklen_t plen = sizeof(peer);
        int cfd = accept4(w->listen_fd, (struct sockaddr *)&peer, &plen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd >= 0) {
            conn_t *c = (conn_t *)calloc(1, sizeof(*c));
            if (!c) { close(cfd); continue; }
            c->fd = cfd; c->file_fd = -1; c->st = ST_HANDSHAKE;
            int one = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

            /* 소켓 튜닝: XLIO 미감지 시에만 적용
             * XLIO가 LD_PRELOAD되어 있으면 setsockopt이 가로채일 수 있고,
             * XLIO 자체가 자체 버퍼 풀(XLIO_TX_BUFS 등)로 송신 흐름 제어를 하므로
             * 커널 SO_SNDBUF/TCP_NOTSENT_LOWAT 적용은 의미 없거나 방해됨. */
            if (!w->cfg->xlio_detected) {
                if (w->cfg->sndbuf > 0) {
                    int v = w->cfg->sndbuf;
                    if (setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)) < 0) {
                        if (w->cfg->verbose >= 1) {
                            fprintf(stdout, "WARN setsockopt(SO_SNDBUF=%d) errno=%d fd=%d\n",
                                    v, errno, cfd);
                            fflush(stdout);
                        }
                    }
                }
#ifdef TCP_NOTSENT_LOWAT
                if (w->cfg->notsent_lowat > 0) {
                    int v = w->cfg->notsent_lowat;
                    if (setsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &v, sizeof(v)) < 0) {
                        if (w->cfg->verbose >= 1) {
                            fprintf(stdout, "WARN setsockopt(TCP_NOTSENT_LOWAT=%d) errno=%d fd=%d\n",
                                    v, errno, cfd);
                            fflush(stdout);
                        }
                    }
                }
#endif
                /* 검증 출력 (verbose>=2) */
                if (w->cfg->verbose >= 2) {
                    int got_sndbuf = -1, got_lowat = -1;
                    socklen_t l = sizeof(int);
                    getsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &got_sndbuf, &l);
#ifdef TCP_NOTSENT_LOWAT
                    l = sizeof(int);
                    getsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &got_lowat, &l);
#endif
                    fprintf(stdout, "SOCKOPT fd=%d SO_SNDBUF=%d TCP_NOTSENT_LOWAT=%d\n",
                            cfd, got_sndbuf, got_lowat);
                    fflush(stdout);
                }
            } else if (w->cfg->verbose >= 2) {
                fprintf(stdout, "DIAG socket_tuning_skipped fd=%d (xlio_detected)\n", cfd);
                fflush(stdout);
            }

            if (mode_uses_ssl(w->cfg->mode)) {
                c->ssl = SSL_new(w->ctx);
                if (!c->ssl) { close(cfd); free(c); continue; }
                SSL_set_fd(c->ssl, cfd);
                SSL_set_accept_state(c->ssl);
            } else {
                c->ssl = NULL;
            }

            if (add_conn(w->epfd, c, EPOLLIN | EPOLLOUT) < 0) { conn_free(c); continue; }
            continue;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        perror("accept4"); break;
    }
}

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    pin_to_cpu(w->cpu);
    fprintf(stderr, "[INFO] worker#%d pinned CPU %d\n", w->id, w->cpu);

    struct epoll_event events[MAX_EVENTS];
    while (!g_stop) {
        int n = epoll_wait(w->epfd, events, MAX_EVENTS, 1000);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); break; }
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == w->listen_fd) accept_loop(w);
            else { conn_t *c = (conn_t *)events[i].data.ptr; if (c) handle_conn_event(w, c, events[i].events); }
        }
    }
    return NULL;
}

/* ================ diagnostics ================ */

static void print_diagnostics(const server_cfg_t *cfg) {
    fprintf(stdout, "\n========== 5-Mode TLS Transfer Server ==========\n");
    fprintf(stdout, "Port             : %d\n", cfg->port);
    fprintf(stdout, "Mode             : %s\n", mode_name(cfg->mode));
    fprintf(stdout, "Workers          : %d\n", cfg->workers);
    fprintf(stdout, "Verbose          : %d\n", cfg->verbose);
    fprintf(stdout, "SW Fallback      : %s\n", cfg->allow_sw_fallback ? "ENABLED" : "DISABLED");
    fprintf(stdout, "XLIO detected    : %s\n", cfg->xlio_detected ? "YES" : "NO");
    if (cfg->xlio_detected) {
        fprintf(stdout, "Socket tuning    : SKIPPED (XLIO active; uses XLIO_TX_BUFS/XLIO_TX_BUF_SIZE)\n");
    } else {
        fprintf(stdout, "Socket tuning    : SO_SNDBUF=%d TCP_NOTSENT_LOWAT=%d %s\n",
                cfg->sndbuf, cfg->notsent_lowat,
                (cfg->sndbuf == 0 && cfg->notsent_lowat == 0) ? "(both 0 → kernel defaults)" : "");
    }
    bool tls_mod = check_kernel_tls_module();
    fprintf(stdout, "Kernel tls module: %s\n", tls_mod ? "LOADED" : "NOT LOADED");
#ifdef SSL_OP_ENABLE_KTLS
    fprintf(stdout, "OpenSSL kTLS     : SUPPORTED\n");
#else
    fprintf(stdout, "OpenSSL kTLS     : NOT SUPPORTED\n");
#endif
    fprintf(stdout, "OpenSSL version  : %s\n", OpenSSL_version(OPENSSL_VERSION));

    /* 모드별 사전 조건 안내 */
    fprintf(stdout, "\n--- Mode preconditions ---\n");
    switch (cfg->mode) {
        case MODE_HTTP:
            fprintf(stdout, "  - No TLS. Client must use http:// scheme.\n");
            break;
        case MODE_OPENSSL:
            fprintf(stdout, "  - OpenSSL SW path (SSL_write).\n");
            break;
        case MODE_SWKTLS:
            fprintf(stdout, "  - kTLS active expected; NIC offload should be OFF\n");
            fprintf(stdout, "    sudo ethtool -K <iface> tls-hw-tx-offload off\n");
            fprintf(stdout, "  - Verify after run: cat /proc/net/tls_stat | grep -i sw\n");
            break;
        case MODE_HWKTLS:
            fprintf(stdout, "  - kTLS active expected; NIC offload should be ON\n");
            fprintf(stdout, "    sudo modprobe tls\n");
            fprintf(stdout, "    sudo ethtool -K <iface> tls-hw-tx-offload on\n");
            fprintf(stdout, "  - Verify: ethtool -S <iface> | grep tls_encrypt\n");
            break;
        case MODE_XLIO_HWKTLS:
            fprintf(stdout, "  - LD_PRELOAD=libxlio.so XLIO_UTLS_TX=1\n");
            fprintf(stdout, "  - NIC offload ON, RDMA stack up\n");
            if (!cfg->xlio_detected)
                fprintf(stdout, "  ⚠ WARNING: XLIO not detected in this process!\n");
            break;
    }
    fprintf(stdout, "================================================\n\n");
    fflush(stdout);
}

/* ================ main ================ */

int main(int argc, char **argv) {
    server_cfg_t cfg;
    parse_args(argc, argv, &cfg);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    print_diagnostics(&cfg);

    SSL_CTX *ctx  = make_ctx(&cfg);                /* HTTP 모드면 NULL */
    int listen_fd = make_listen_socket(cfg.port);

    fprintf(stdout, "Server started: port=%d mode=%s workers=%d xlio=%d fallback=%d\n",
            cfg.port, mode_name(cfg.mode), cfg.workers,
            cfg.xlio_detected ? 1 : 0, cfg.allow_sw_fallback ? 1 : 0);
    fflush(stdout);

    worker_t workers[MAX_WORKERS]; memset(workers, 0, sizeof(workers));
    for (int i = 0; i < cfg.workers; ++i) {
        workers[i].id = i;
        workers[i].cpu = pick_nth_allowed_cpu(i);
        workers[i].listen_fd = listen_fd;
        workers[i].ctx = ctx;
        workers[i].cfg = &cfg;
        workers[i].epfd = epoll_create1(EPOLL_CLOEXEC);
        if (workers[i].epfd < 0) die_perror("epoll_create1");

        struct epoll_event ev; memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLEXCLUSIVE; ev.data.fd = listen_fd;
        if (epoll_ctl(workers[i].epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) die_perror("epoll_ctl listen");
        if (pthread_create(&workers[i].tid, NULL, worker_main, &workers[i]) != 0) die_perror("pthread_create");
    }

    for (int i = 0; i < cfg.workers; ++i) {
        pthread_join(workers[i].tid, NULL);
        close(workers[i].epfd);
    }
    close(listen_fd);
    if (ctx) SSL_CTX_free(ctx);
    return 0;
}