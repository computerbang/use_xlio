/* =====================================================================
 * Plan A: Server 3 rewritten for XLIO R2C correctness.
 *
 * Architecture:
 *   - Each worker creates its OWN listen socket using SO_REUSEPORT.
 *   - Each worker accept4()s its OWN clients and handles them end-to-end.
 *   - Accept thread == TX thread == XLIO ring owner (R2C invariant).
 *
 * HWKTLS activation:
 *   - SSL_OP_ENABLE_KTLS on SSL_CTX (when mode = HWKTLS).
 *   - After SSL_accept(), BIO_get_ktls_send() is checked ONCE.
 *   - No manual kTLS probe. No zero-info setsockopt. No DEK-cache jitter.
 *   - If kTLS inactive in HWKTLS mode: close connection unless
 *     ALLOW_SW_FALLBACK=1 is explicitly set.
 *
 * Hot path:
 *   - No TCP_CORK. TCP_NODELAY only.
 *   - No SO_SNDBUF / TCP_NOTSENT_LOWAT (delegated to XLIO env vars).
 *   - Only MEASURE_BEGIN / MEASURE_END go to stdout during the send loop.
 *
 * Build:
 *   gcc -O2 -pthread -Wall -Wextra -D_GNU_SOURCE -DOPENSSL_KTLS=1 \
 *       -o server3_planA server3_planA_r2c.c -lssl -lcrypto
 *
 * Run (HWKTLS + XLIO R2C):
 *   sudo modprobe tls
 *   LD_PRELOAD=/usr/lib/libxlio.so.3.61.2 \
 *   XLIO_UTLS_TX=1 XLIO_UTLS_RX=0 \
 *   XLIO_WORKER_THREADS=0 \
 *   XLIO_TSO=1 \
 *   XLIO_TX_BUF_SIZE=131072 \
 *   XLIO_TCP_SEND_BUFFER_SIZE=4194304 \
 *   XLIO_RING_ALLOCATION_LOGIC_TX=20 \
 *   XLIO_TRACELEVEL=0 \
 *   VERBOSE=0 \
 *   ./server3_planA <port> HWKTLS <cert.pem> <key.pem> <base_dir> <workers>
 * ===================================================================== */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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

#define MAX_WORKERS    128
#define MAX_EVENTS     256
#define REQ_BUFSZ      8192
#define HDR_BUFSZ      1024
#define FILE_CHUNK     (256 * 1024)
#define LISTEN_BACKLOG 4096

typedef enum { MODE_OPENSSL = 0, MODE_HWKTLS = 1 } tls_mode_t;

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
    int        verbose;            /* env VERBOSE=0..3 */
    bool       allow_sw_fallback;  /* env ALLOW_SW_FALLBACK=1 */
} server_cfg_t;

typedef struct conn {
    int           fd;
    SSL          *ssl;
    conn_state_t  st;
    bool          hwktls_active;
    bool          measure_begun;

    char          req[REQ_BUFSZ];
    size_t        req_len;
    char          relpath[NAME_MAX + 1];

    int           file_fd;
    off_t         file_size;

    char          hdr[HDR_BUFSZ];
    size_t        hdr_len;
    size_t        hdr_off;

    unsigned char *buf;
    size_t         buf_cap;
    size_t         buf_len;
    size_t         buf_off;
} conn_t;

typedef struct worker {
    int                 id;
    int                 cpu;
    int                 epfd;
    int                 listen_fd;
    SSL_CTX            *ctx;
    const server_cfg_t *cfg;
    pthread_t           tid;
} worker_t;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int s) { (void)s; g_stop = 1; }

static uint64_t now_ns_raw(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void die_perror(const char *m) { perror(m); exit(EXIT_FAILURE); }

static void die_ssl(const char *m) {
    fprintf(stderr, "FATAL: %s\n", m);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

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
    int cpus[CPU_SETSIZE];
    int cnt = 0;
    for (int i = 0; i < CPU_SETSIZE; ++i)
        if (CPU_ISSET(i, &allowed)) cpus[cnt++] = i;
    return cnt ? cpus[n % cnt] : 0;
}

static void pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
        perror("pthread_setaffinity_np");
}

/* =========================================================
 * Per-worker listen socket created INSIDE the worker thread.
 * This is the heart of Plan A: the socket's XLIO ring is
 * bound to the creating thread's context.
 * ========================================================= */
static int make_worker_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die_perror("socket");

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die_perror("bind");
    if (listen(fd, LISTEN_BACKLOG) < 0)
        die_perror("listen");
    if (set_nonblock(fd) < 0)
        die_perror("set_nonblock(listen)");
    return fd;
}

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
        if (src[0] == '%' &&
            isxdigit((unsigned char)src[1]) &&
            isxdigit((unsigned char)src[2])) {
            char hex[3] = {src[1], src[2], 0};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
    return (size_t)(dst - s);
}

static int safe_join_under_base(const char *base, const char *name,
                                char out[PATH_MAX]) {
    char realb[PATH_MAX];
    if (!realpath(base, realb)) return -1;

    char cand[PATH_MAX];
    if (snprintf(cand, sizeof(cand), "%s/%s", base, name) >= (int)sizeof(cand))
        return -1;

    char *realc = realpath(cand, NULL);
    if (!realc) return -1;

    size_t bl = strlen(realb);
    int ok = (strncmp(realb, realc, bl) == 0) &&
             (realc[bl] == '/' || realc[bl] == '\0');
    if (ok) {
        strncpy(out, realc, PATH_MAX - 1);
        out[PATH_MAX - 1] = '\0';
    }
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
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = events | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = c;
    return epoll_ctl(epfd, op, c->fd, &ev);
}
static int arm_conn(int epfd, conn_t *c, uint32_t e) {
    return conn_ctl(epfd, EPOLL_CTL_MOD, c, e);
}
static int add_conn(int epfd, conn_t *c, uint32_t e) {
    return conn_ctl(epfd, EPOLL_CTL_ADD, c, e);
}

static int ssl_is_ktls_send_active(SSL *ssl) {
    BIO *wbio = SSL_get_wbio(ssl);
    if (!wbio) return 0;
    long r = BIO_ctrl(wbio, BIO_CTRL_GET_KTLS_SEND, 0, NULL);
    return r > 0 ? 1 : 0;
}

static ssize_t ssl_read_nb(SSL *ssl, void *buf, size_t cap, int *want) {
    *want = 0;
    int n = SSL_read(ssl, buf, (int)cap);
    if (n > 0) return n;
    int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_WANT_READ)  { *want = EPOLLIN;  errno = EAGAIN; return -1; }
    if (e == SSL_ERROR_WANT_WRITE) { *want = EPOLLOUT; errno = EAGAIN; return -1; }
    if (e == SSL_ERROR_ZERO_RETURN) return 0;
    errno = EIO;
    return -1;
}

static ssize_t ssl_write_nb(SSL *ssl, const void *buf, size_t len, int *want) {
    *want = 0;
    int n = SSL_write(ssl, buf, (int)len);
    if (n > 0) return n;
    int e = SSL_get_error(ssl, n);
    if (e == SSL_ERROR_WANT_READ)  { *want = EPOLLIN;  errno = EAGAIN; return -1; }
    if (e == SSL_ERROR_WANT_WRITE) { *want = EPOLLOUT; errno = EAGAIN; return -1; }
    errno = EIO;
    return -1;
}

static ssize_t raw_send_nb(int fd, const void *buf, size_t len) {
    for (;;) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        return -1;
    }
}

/* When kTLS is active, sending plaintext via raw send() hands it directly
 * to the kernel/XLIO TLS TX path — NIC encrypts. When kTLS is inactive,
 * OpenSSL does the encryption via SSL_write(). */
static int send_app_data(conn_t *c, const void *buf, size_t len, int *want) {
    *want = 0;
    if (c->hwktls_active) {
        ssize_t n = raw_send_nb(c->fd, buf, len);
        if (n > 0) return (int)n;
        if (n == 0) return -1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    ssize_t n = ssl_write_nb(c->ssl, buf, len, want);
    if (n > 0) return (int)n;
    if (n == 0) return -1;
    if (errno == EAGAIN) return 0;
    return -1;
}

static int flush_hdr(conn_t *c, int epfd) {
    while (c->hdr_off < c->hdr_len) {
        int want = 0;
        int n = send_app_data(c, c->hdr + c->hdr_off,
                              c->hdr_len - c->hdr_off, &want);
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
    c->buf_off = 0;
    c->buf_len = 0;
    for (;;) {
        ssize_t n = read(c->file_fd, c->buf, c->buf_cap);
        if (n > 0) { c->buf_len = (size_t)n; return 1; }
        if (n == 0) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
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
            int n = send_app_data(c, c->buf + c->buf_off,
                                  c->buf_len - c->buf_off, &want);
            if (n > 0) { c->buf_off += (size_t)n; continue; }
            if (n == 0) {
                if (arm_conn(epfd, c, want ? (uint32_t)want : EPOLLOUT) < 0) return -1;
                return 0;
            }
            return -1;
        }
    }
}

static int build_simple_response(conn_t *c, int code, const char *reason,
                                 const char *body) {
    int n = snprintf(c->hdr, sizeof(c->hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n%s",
        code, reason, strlen(body), body);
    if (n <= 0 || n >= (int)sizeof(c->hdr)) return -1;
    c->hdr_len = (size_t)n;
    c->hdr_off = 0;
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
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lld\r\n"
        "Connection: close\r\n\r\n",
        (long long)c->file_size);
    if (n <= 0 || n >= (int)sizeof(c->hdr)) return -1;
    c->hdr_len = (size_t)n;
    c->hdr_off = 0;
    return 0;
}

static int parse_request_line(conn_t *c) {
    char method[16]  = {0};
    char target[PATH_MAX] = {0};
    char version[32] = {0};
    if (sscanf(c->req, "%15s %4095s %31s", method, target, version) != 3) return -1;
    if (strcmp(method, "GET") != 0) return -1;
    if (strncmp(version, "HTTP/1.1", 8) != 0 &&
        strncmp(version, "HTTP/1.0", 8) != 0) return -1;
    if (target[0] != '/') return -1;
    const char *p = target + 1;
    while (*p == '/') p++;
    if (!*p) return -1;
    size_t plen = strcspn(p, "?");
    if (!plen || plen > NAME_MAX) return -1;
    memcpy(c->relpath, p, plen);
    c->relpath[plen] = '\0';
    url_decode(c->relpath);
    if (strstr(c->relpath, "..") || strchr(c->relpath, '\\')) return -1;
    return 0;
}

/* ============ State handlers ============ */

static void handle_handshake(worker_t *w, conn_t *c) {
    int r = SSL_accept(c->ssl);
    if (r == 1) {
        if (w->cfg->mode == MODE_HWKTLS) {
            c->hwktls_active = ssl_is_ktls_send_active(c->ssl) ? true : false;
            if (!c->hwktls_active) {
                if (w->cfg->allow_sw_fallback) {
                    /* Silent SW fallback, allowed by env */
                } else {
                    fprintf(stdout,
                        "ERROR ktls_not_active fd=%d — closing. "
                        "Set ALLOW_SW_FALLBACK=1 to permit SW fallback.\n", c->fd);
                    fflush(stdout);
                    c->st = ST_CLOSING;
                    return;
                }
            }
            if (w->cfg->verbose >= 2) {
                fprintf(stdout, "HANDSHAKE_OK fd=%d mode=HWKTLS ktls_tx=%d\n",
                        c->fd, c->hwktls_active ? 1 : 0);
                fflush(stdout);
            }
        } else {
            c->hwktls_active = false;
            if (w->cfg->verbose >= 2) {
                fprintf(stdout, "HANDSHAKE_OK fd=%d mode=OPENSSL\n", c->fd);
                fflush(stdout);
            }
        }
        c->st = ST_READ_REQ;
        if (arm_conn(w->epfd, c, EPOLLIN) < 0) c->st = ST_CLOSING;
        return;
    }
    int e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ)  { if (arm_conn(w->epfd, c, EPOLLIN)  < 0) c->st = ST_CLOSING; return; }
    if (e == SSL_ERROR_WANT_WRITE) { if (arm_conn(w->epfd, c, EPOLLOUT) < 0) c->st = ST_CLOSING; return; }
    if (w->cfg->verbose >= 1) {
        fprintf(stdout, "ERROR handshake fd=%d ssl_error=%d\n", c->fd, e);
        fflush(stdout);
    }
    c->st = ST_CLOSING;
}

static void handle_read_req(worker_t *w, conn_t *c) {
    for (;;) {
        int want = 0;
        ssize_t n = ssl_read_nb(c->ssl, c->req + c->req_len,
                                sizeof(c->req) - 1 - c->req_len, &want);
        if (n > 0) {
            c->req_len += (size_t)n;
            c->req[c->req_len] = '\0';
        } else if (n == 0) {
            c->st = ST_CLOSING;
            return;
        } else {
            if (errno == EAGAIN) {
                if (arm_conn(w->epfd, c, want ? (uint32_t)want : EPOLLIN) < 0)
                    c->st = ST_CLOSING;
            } else {
                c->st = ST_CLOSING;
            }
            return;
        }
        if (!req_line_complete(c->req, c->req_len)) {
            if (c->req_len >= sizeof(c->req) - 1) {
                if (build_simple_response(c, 400, "Bad Request", "bad request\n") < 0) {
                    c->st = ST_CLOSING;
                    return;
                }
                c->st = ST_SEND_HDR;
            } else {
                continue;
            }
        } else {
            if (parse_request_line(c) < 0) {
                if (build_simple_response(c, 404, "Not Found", "not found\n") < 0) {
                    c->st = ST_CLOSING;
                    return;
                }
                c->st = ST_SEND_HDR;
            } else if (build_file_response(c, w->cfg) < 0) {
                if (build_simple_response(c, 404, "Not Found", "not found\n") < 0) {
                    c->st = ST_CLOSING;
                    return;
                }
                c->st = ST_SEND_HDR;
            } else {
                if (w->cfg->verbose >= 1) {
                    fprintf(stdout, "REQUEST fd=%d path=\"%s\" size=%lld\n",
                        c->fd, c->relpath, (long long)c->file_size);
                    fflush(stdout);
                }
                c->st = ST_SEND_HDR;
            }
        }
        return;
    }
}

static void handle_send_hdr(worker_t *w, conn_t *c) {
    int r = flush_hdr(c, w->epfd);
    if (r < 0)      { c->st = ST_CLOSING; }
    else if (r == 1) c->st = (c->file_fd >= 0) ? ST_SEND_FILE : ST_CLOSING;
}

static void handle_send_file(worker_t *w, conn_t *c) {
    if (!c->measure_begun) {
        /* Only write in the hot path: measurement markers. */
        fprintf(stdout, "MEASURE_BEGIN fd=%d path=\"%s\" size=%lld t_ns=%" PRIu64 "\n",
            c->fd, c->relpath, (long long)c->file_size, now_ns_raw());
        fflush(stdout);
        c->measure_begun = true;
    }
    int r = flush_file(c, w->epfd);
    if (r < 0) {
        c->st = ST_CLOSING;
    } else if (r == 1) {
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
            case ST_READ_REQ:  handle_read_req(w, c);  if (c->st == ST_SEND_HDR) continue; return;
            case ST_SEND_HDR:  handle_send_hdr(w, c);  if (c->st == ST_SEND_FILE) continue; return;
            case ST_SEND_FILE: handle_send_file(w, c); return;
            default: break;
        }
    }
    epoll_ctl(w->epfd, EPOLL_CTL_DEL, c->fd, NULL);
    conn_free(c);
}

/* Accept all pending connections on our own listen_fd. */
static void accept_loop(worker_t *w) {
    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept4(w->listen_fd, (struct sockaddr *)&peer, &plen,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd >= 0) {
            int one = 1;
            setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            /* NO TCP_CORK. NO SO_SNDBUF. NO TCP_NOTSENT_LOWAT.
             * XLIO_TX_BUF_SIZE and XLIO_TCP_SEND_BUFFER_SIZE own the buffering. */
            conn_t *c = calloc(1, sizeof(*c));
            if (!c) { close(cfd); continue; }
            c->fd      = cfd;
            c->file_fd = -1;
            c->st      = ST_HANDSHAKE;
            c->ssl = SSL_new(w->ctx);
            if (!c->ssl) { close(cfd); free(c); continue; }
            SSL_set_fd(c->ssl, cfd);
            SSL_set_accept_state(c->ssl);
            if (add_conn(w->epfd, c, EPOLLIN | EPOLLOUT) < 0) {
                conn_free(c);
                continue;
            }
            continue;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        perror("accept4");
        break;
    }
}

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    pin_to_cpu(w->cpu);

    /* Create listen_fd and epoll IN THIS THREAD.
     * XLIO binds the ring context to this thread for both. */
    w->listen_fd = make_worker_listen_socket(w->cfg->port);
    w->epfd      = epoll_create1(EPOLL_CLOEXEC);
    if (w->epfd < 0) die_perror("epoll_create1");

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events  = EPOLLIN;   /* Kernel SO_REUSEPORT distributes — no EPOLLEXCLUSIVE needed */
    ev.data.fd = w->listen_fd;
    if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->listen_fd, &ev) < 0)
        die_perror("epoll_ctl listen");

    fprintf(stderr, "[INFO] worker#%d CPU=%d listen_fd=%d (SO_REUSEPORT)\n",
        w->id, w->cpu, w->listen_fd);

    struct epoll_event events[MAX_EVENTS];
    while (!g_stop) {
        int n = epoll_wait(w->epfd, events, MAX_EVENTS, 1000);
        if (n < 0) { if (errno == EINTR) continue; perror("epoll_wait"); break; }
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == w->listen_fd) {
                accept_loop(w);
            } else {
                conn_t *c = (conn_t *)events[i].data.ptr;
                if (c) handle_conn_event(w, c, events[i].events);
            }
        }
    }

    close(w->listen_fd);
    close(w->epfd);
    return NULL;
}

/* ============ SSL_CTX / main ============ */

static SSL_CTX *make_ctx(const server_cfg_t *cfg) {
    OPENSSL_init_ssl(0, NULL);  /* modern OpenSSL 3.x init */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die_ssl("SSL_CTX_new");

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) die_ssl("min TLS1.2");
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) != 1) die_ssl("max TLS1.2");
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256") != 1)
        die_ssl("cipher list");

#ifdef SSL_OP_ENABLE_KTLS
    if (cfg->mode == MODE_HWKTLS) {
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        if (cfg->verbose >= 1) {
            fprintf(stdout, "INIT SSL_OP_ENABLE_KTLS set\n");
            fflush(stdout);
        }
    }
#else
    if (cfg->mode == MODE_HWKTLS) {
        fprintf(stderr, "OpenSSL not built with enable-ktls\n");
        exit(EXIT_FAILURE);
    }
#endif

    if (SSL_CTX_use_certificate_file(ctx, cfg->cert, SSL_FILETYPE_PEM) != 1) die_ssl("cert");
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key, SSL_FILETYPE_PEM) != 1) die_ssl("key");
    if (SSL_CTX_check_private_key(ctx) != 1) die_ssl("check key");
    return ctx;
}

static tls_mode_t parse_mode(const char *s) {
    if (!strcasecmp(s, "OPENSSL")) return MODE_OPENSSL;
    if (!strcasecmp(s, "HWKTLS"))  return MODE_HWKTLS;
    fprintf(stderr, "Invalid mode: %s (use OPENSSL|HWKTLS)\n", s);
    exit(EXIT_FAILURE);
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s <port> <OPENSSL|HWKTLS> <cert.pem> <key.pem> <base_dir> [workers]\n"
        "Env  : VERBOSE=0..3 (default 1), ALLOW_SW_FALLBACK=0|1 (default 0)\n",
        p);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc != 6 && argc != 7) usage(argv[0]);

    server_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port    = atoi(argv[1]);
    cfg.mode    = parse_mode(argv[2]);
    snprintf(cfg.cert,     sizeof(cfg.cert),     "%s", argv[3]);
    snprintf(cfg.key,      sizeof(cfg.key),      "%s", argv[4]);
    snprintf(cfg.base_dir, sizeof(cfg.base_dir), "%s", argv[5]);
    cfg.workers = (argc == 7) ? atoi(argv[6]) : 1;

    if (cfg.port <= 0 || cfg.port > 65535) usage(argv[0]);
    if (cfg.workers <= 0) cfg.workers = 1;
    if (cfg.workers > MAX_WORKERS) cfg.workers = MAX_WORKERS;

    const char *v  = getenv("VERBOSE");
    cfg.verbose = v ? atoi(v) : 1;
    const char *fb = getenv("ALLOW_SW_FALLBACK");
    cfg.allow_sw_fallback = (fb && atoi(fb) == 1);

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    setvbuf(stdout, NULL, _IOLBF, 0);

    SSL_CTX *ctx = make_ctx(&cfg);

    fprintf(stdout,
        "Plan A (R2C) port=%d mode=%s workers=%d verbose=%d sw_fb=%d "
        "base_dir=%s\n",
        cfg.port, cfg.mode == MODE_HWKTLS ? "HWKTLS" : "OPENSSL",
        cfg.workers, cfg.verbose, cfg.allow_sw_fallback, cfg.base_dir);
    fflush(stdout);

    worker_t workers[MAX_WORKERS];
    memset(workers, 0, sizeof(workers));
    for (int i = 0; i < cfg.workers; ++i) {
        workers[i].id  = i;
        workers[i].cpu = pick_nth_allowed_cpu(i);
        workers[i].ctx = ctx;
        workers[i].cfg = &cfg;
        if (pthread_create(&workers[i].tid, NULL, worker_main, &workers[i]) != 0)
            die_perror("pthread_create");
    }
    for (int i = 0; i < cfg.workers; ++i)
        pthread_join(workers[i].tid, NULL);

    SSL_CTX_free(ctx);
    return 0;
}