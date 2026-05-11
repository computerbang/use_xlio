#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/tls.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BACKLOG        1
#define REQ_BUF_SZ     8192
#define FILE_BUF_SZ    65536
#define HDR_BUF_SZ     1024

typedef enum tls_mode_e {
    MODE_OPENSSL = 0,
    MODE_SWKTLS  = 1,
    MODE_HWKTLS  = 2
} tls_mode_t;

typedef struct server_cfg_s {
    int        port;
    tls_mode_t mode;
    char       cert_path[PATH_MAX];
    char       key_path[PATH_MAX];
    char       base_dir[PATH_MAX];
    int        workers_hint;
    int        sndbuf_bytes;
    int        notsent_lowat_bytes;
} server_cfg_t;

typedef struct stats_s {
    uint64_t request_read_calls;
    uint64_t request_read_bytes;
    uint64_t request_read_ns_total;
    uint64_t request_read_ns_max;

    uint64_t hdr_write_calls;
    uint64_t hdr_write_bytes;
    uint64_t hdr_write_ns_total;
    uint64_t hdr_write_ns_max;

    uint64_t file_read_calls;
    uint64_t file_read_bytes;
    uint64_t file_read_ns_total;
    uint64_t file_read_ns_max;

    uint64_t ssl_write_calls;
    uint64_t ssl_write_bytes;
    uint64_t ssl_write_ns_total;
    uint64_t ssl_write_ns_max;

    uint64_t sf_calls;
    uint64_t sf_bytes;
    uint64_t sf_ns_total;
    uint64_t sf_ns_max;

    uint64_t sf_success_calls;
    uint64_t sf_success_bytes;
    uint64_t sf_success_ns_total;
    uint64_t sf_success_ns_max;

    uint64_t sf_eagain_calls;
    uint64_t sf_eintr_calls;
    uint64_t sf_zero_returns;

    uint64_t payload_bytes;
} stats_t;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo) {
    (void)signo;
    g_stop = 1;
}

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void die_ssl(const char *msg) {
    fprintf(stderr, "FATAL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void add_sample(uint64_t delta, uint64_t *total, uint64_t *maxv) {
    *total += delta;
    if (delta > *maxv) *maxv = delta;
}

static int getenv_int_or_default(const char *name, int defval) {
    const char *s = getenv(name);
    char *end = NULL;
    long v;

    if (!s || !*s) return defval;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0 || v > INT_MAX) {
        fprintf(stderr, "Invalid %s=%s\n", name, s);
        exit(EXIT_FAILURE);
    }

    return (int)v;
}

static const char *mode_str(tls_mode_t mode) {
    switch (mode) {
        case MODE_OPENSSL: return "OPENSSL";
        case MODE_SWKTLS:  return "SWKTLS";
        case MODE_HWKTLS:  return "HWKTLS";
        default:           return "UNKNOWN";
    }
}

static tls_mode_t parse_mode(const char *s) {
    if (strcasecmp(s, "OPENSSL") == 0) return MODE_OPENSSL;
    if (strcasecmp(s, "SWKTLS")  == 0) return MODE_SWKTLS;
    if (strcasecmp(s, "HWKTLS")  == 0) return MODE_HWKTLS;

    fprintf(stderr, "Invalid mode: %s\n", s);
    fprintf(stderr, "Valid modes: OPENSSL | SWKTLS | HWKTLS\n");
    exit(EXIT_FAILURE);
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <port> <OPENSSL|SWKTLS|HWKTLS> <cert.pem> <key.pem> <base_dir> [workers_hint]\n"
            "Environment:\n"
            "  SNDBUF=<bytes>          set SO_SNDBUF on accepted client socket\n"
            "  NOTSENT_LOWAT=<bytes>   set TCP_NOTSENT_LOWAT on accepted client socket\n",
            prog);
    exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv, server_cfg_t *cfg) {
    if (argc != 6 && argc != 7) {
        usage(argv[0]);
    }

    memset(cfg, 0, sizeof(*cfg));

    cfg->port = atoi(argv[1]);
    if (cfg->port <= 0 || cfg->port > 65535) {
        fprintf(stderr, "Invalid port: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    cfg->mode = parse_mode(argv[2]);
    cfg->workers_hint = (argc == 7) ? atoi(argv[6]) : 1;
    if (cfg->workers_hint <= 0) cfg->workers_hint = 1;
    cfg->sndbuf_bytes = getenv_int_or_default("SNDBUF", 0);
    cfg->notsent_lowat_bytes = getenv_int_or_default("NOTSENT_LOWAT", 0);

    if (snprintf(cfg->cert_path, sizeof(cfg->cert_path), "%s", argv[3]) >= (int)sizeof(cfg->cert_path) ||
        snprintf(cfg->key_path,  sizeof(cfg->key_path),  "%s", argv[4]) >= (int)sizeof(cfg->key_path)  ||
        snprintf(cfg->base_dir,  sizeof(cfg->base_dir),  "%s", argv[5]) >= (int)sizeof(cfg->base_dir)) {
        fprintf(stderr, "Path too long\n");
        exit(EXIT_FAILURE);
    }
}

static int create_listen_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        close(fd);
        die("setsockopt(SO_REUSEADDR)");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        die("bind");
    }

    if (listen(fd, BACKLOG) < 0) {
        close(fd);
        die("listen");
    }

    return fd;
}

static SSL_CTX *create_ssl_ctx(const server_cfg_t *cfg) {
    SSL_CTX *ctx = NULL;

    OPENSSL_init_ssl(0, NULL);
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) die_ssl("SSL_CTX_new");

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        die_ssl("SSL_CTX_set_min_proto_version");
    }
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) != 1) {
        die_ssl("SSL_CTX_set_max_proto_version");
    }

    if (SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256") != 1) {
        die_ssl("SSL_CTX_set_cipher_list");
    }

    if (cfg->mode == MODE_SWKTLS || cfg->mode == MODE_HWKTLS) {
#ifdef SSL_OP_ENABLE_KTLS
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
#else
        fprintf(stderr, "OpenSSL build does not support SSL_OP_ENABLE_KTLS\n");
        exit(EXIT_FAILURE);
#endif
    }

    if (SSL_CTX_use_certificate_file(ctx, cfg->cert_path, SSL_FILETYPE_PEM) != 1) {
        die_ssl("SSL_CTX_use_certificate_file");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key_path, SSL_FILETYPE_PEM) != 1) {
        die_ssl("SSL_CTX_use_PrivateKey_file");
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        die_ssl("SSL_CTX_check_private_key");
    }

    return ctx;
}

static void apply_socket_tuning(int cfd, const server_cfg_t *cfg) {
    int v;
    socklen_t l;

    if (cfg->sndbuf_bytes > 0) {
        if (setsockopt(cfd, SOL_SOCKET, SO_SNDBUF,
                       &cfg->sndbuf_bytes, sizeof(cfg->sndbuf_bytes)) < 0) {
            perror("setsockopt(SO_SNDBUF)");
        }
    }

#ifdef TCP_NOTSENT_LOWAT
    if (cfg->notsent_lowat_bytes > 0) {
        if (setsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT,
                       &cfg->notsent_lowat_bytes, sizeof(cfg->notsent_lowat_bytes)) < 0) {
            perror("setsockopt(TCP_NOTSENT_LOWAT)");
        }
    }
#else
    if (cfg->notsent_lowat_bytes > 0) {
        fprintf(stderr, "TCP_NOTSENT_LOWAT not available in current headers\n");
    }
#endif

    l = sizeof(v);
    if (getsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &v, &l) == 0) {
        fprintf(stderr, "SO_SNDBUF effective=%d requested=%d\n", v, cfg->sndbuf_bytes);
    }

#ifdef TCP_NOTSENT_LOWAT
    l = sizeof(v);
    if (getsockopt(cfd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &v, &l) == 0) {
        fprintf(stderr, "TCP_NOTSENT_LOWAT effective=%d requested=%d\n", v, cfg->notsent_lowat_bytes);
    }
#endif
}

static int ssl_write_all_counted(SSL *ssl, const void *buf, size_t len, stats_t *st, bool header_write) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;

    while (sent < len) {
        uint64_t t0 = now_ns();
        int n = SSL_write(ssl, p + sent, (int)(len - sent));
        uint64_t t1 = now_ns();
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            fprintf(stderr, "SSL_write failed, SSL_get_error=%d\n", err);
            ERR_print_errors_fp(stderr);
            return -1;
        }
        if (header_write) {
            st->hdr_write_calls++;
            st->hdr_write_bytes += (uint64_t)n;
            add_sample(t1 - t0, &st->hdr_write_ns_total, &st->hdr_write_ns_max);
        } else {
            st->ssl_write_calls++;
            st->ssl_write_bytes += (uint64_t)n;
            add_sample(t1 - t0, &st->ssl_write_ns_total, &st->ssl_write_ns_max);
            st->payload_bytes += (uint64_t)n;
        }
        sent += (size_t)n;
    }
    return 0;
}

static ssize_t ssl_read_request(SSL *ssl, char *buf, size_t bufsz, stats_t *st) {
    size_t total = 0;

    while (total + 1 < bufsz) {
        uint64_t t0 = now_ns();
        int n = SSL_read(ssl, buf + total, (int)(bufsz - total - 1));
        uint64_t t1 = now_ns();
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_ZERO_RETURN) {
                break;
            }
            fprintf(stderr, "SSL_read failed, SSL_get_error=%d\n", err);
            ERR_print_errors_fp(stderr);
            return -1;
        }

        st->request_read_calls++;
        st->request_read_bytes += (uint64_t)n;
        add_sample(t1 - t0, &st->request_read_ns_total, &st->request_read_ns_max);

        total += (size_t)n;
        buf[total] = '\0';

        if (strstr(buf, "\r\n\r\n") != NULL) {
            return (ssize_t)total;
        }
    }

    return (ssize_t)total;
}

static bool parse_http_get_path(const char *req, char *out_relpath, size_t outsz) {
    char method[16];
    char target[PATH_MAX];
    char version[32];

    if (sscanf(req, "%15s %4095s %31s", method, target, version) != 3) {
        return false;
    }
    if (strcmp(method, "GET") != 0) {
        return false;
    }
    if (strncmp(version, "HTTP/1.1", 8) != 0 && strncmp(version, "HTTP/1.0", 8) != 0) {
        return false;
    }
    if (target[0] != '/') {
        return false;
    }

    const char *p = target + 1;
    while (*p == '/') p++;

    if (*p == '\0') {
        return false;
    }
    if (strstr(p, "..") != NULL) {
        return false;
    }
    if (strchr(p, '\\') != NULL) {
        return false;
    }

    if (snprintf(out_relpath, outsz, "%s", p) >= (int)outsz) {
        return false;
    }

    return true;
}

static bool build_full_path(const char *base_dir, const char *relpath, char *out, size_t outsz) {
    if (snprintf(out, outsz, "%s/%s", base_dir, relpath) >= (int)outsz) {
        return false;
    }
    return true;
}

static int send_http_error(SSL *ssl, int code, const char *reason, const char *body, stats_t *st) {
    char hdr[HDR_BUF_SZ];
    int body_len = (int)strlen(body);

    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     code, reason, body_len);
    if (n < 0 || n >= (int)sizeof(hdr)) {
        return -1;
    }

    if (ssl_write_all_counted(ssl, hdr, (size_t)n, st, true) < 0) return -1;
    if (ssl_write_all_counted(ssl, body, (size_t)body_len, st, true) < 0) return -1;
    return 0;
}

static int send_http_ok_header(SSL *ssl, off_t file_size, stats_t *st) {
    char hdr[HDR_BUF_SZ];

    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Length: %lld\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     (long long)file_size);

    if (n < 0 || n >= (int)sizeof(hdr)) {
        return -1;
    }

    return ssl_write_all_counted(ssl, hdr, (size_t)n, st, true);
}

static int enable_hw_ktls_zerocopy_if_possible(int sockfd) {
#if defined(SOL_TLS) && defined(TLS_TX_ZEROCOPY_RO)
    int one = 1;
    if (setsockopt(sockfd, SOL_TLS, TLS_TX_ZEROCOPY_RO, &one, sizeof(one)) < 0) {
        perror("setsockopt(TLS_TX_ZEROCOPY_RO)");
        return -1;
    }
    return 0;
#else
    (void)sockfd;
    fprintf(stderr, "TLS_TX_ZEROCOPY_RO not available in current headers\n");
    return -1;
#endif
}

static int send_file_openssl(SSL *ssl, int file_fd, stats_t *st) {
    unsigned char buf[FILE_BUF_SZ];

    for (;;) {
        uint64_t t0 = now_ns();
        ssize_t nr = read(file_fd, buf, sizeof(buf));
        uint64_t t1 = now_ns();
        if (nr < 0) {
            if (errno == EINTR) continue;
            perror("read(file)");
            return -1;
        }
        st->file_read_calls++;
        if (nr > 0) st->file_read_bytes += (uint64_t)nr;
        add_sample(t1 - t0, &st->file_read_ns_total, &st->file_read_ns_max);
        if (nr == 0) {
            break;
        }
        if (ssl_write_all_counted(ssl, buf, (size_t)nr, st, false) < 0) {
            return -1;
        }
    }

    return 0;
}

static int send_file_sendfile(int sockfd, int file_fd, off_t file_size, stats_t *st) {
    off_t off = 0;

    while (off < file_size) {
        uint64_t t0 = now_ns();
        ssize_t n = sendfile(sockfd, file_fd, &off, (size_t)(file_size - off));
        uint64_t t1 = now_ns();
        uint64_t elapsed = t1 - t0;

        st->sf_calls++;
        add_sample(elapsed, &st->sf_ns_total, &st->sf_ns_max);

        if (n < 0) {
            if (errno == EINTR) {
                st->sf_eintr_calls++;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                st->sf_eagain_calls++;
                continue;
            }
            perror("sendfile");
            return -1;
        }

        if (n == 0) {
            st->sf_zero_returns++;
            break;
        }

        st->sf_success_calls++;
        st->sf_success_bytes += (uint64_t)n;
        add_sample(elapsed, &st->sf_success_ns_total, &st->sf_success_ns_max);

        st->sf_bytes += (uint64_t)n;
        st->payload_bytes += (uint64_t)n;
    }

    if (off != file_size) {
        fprintf(stderr, "sendfile incomplete: sent=%lld expected=%lld\n",
                (long long)off, (long long)file_size);
        return -1;
    }

    return 0;
}

static void print_event_stats(const stats_t *st, const server_cfg_t *cfg, const char *relpath) {
    double sf_ns_avg = st->sf_calls
        ? (double)st->sf_ns_total / (double)st->sf_calls
        : 0.0;
    double sf_success_ns_avg = st->sf_success_calls
        ? (double)st->sf_success_ns_total / (double)st->sf_success_calls
        : 0.0;

    fprintf(stderr,
            "EVENT_STATS mode=%s file=%s"
            " request_read_calls=%llu request_read_bytes=%llu request_read_ns_total=%llu request_read_ns_max=%llu"
            " hdr_write_calls=%llu hdr_write_bytes=%llu hdr_write_ns_total=%llu hdr_write_ns_max=%llu"
            " file_read_calls=%llu file_read_bytes=%llu file_read_ns_total=%llu file_read_ns_max=%llu"
            " ssl_write_calls=%llu ssl_write_bytes=%llu ssl_write_ns_total=%llu ssl_write_ns_max=%llu"
            " sf_calls=%llu sf_bytes=%llu sf_ns_total=%llu sf_ns_avg=%.1f sf_ns_max=%llu"
            " sf_success_calls=%llu sf_success_bytes=%llu sf_success_ns_total=%llu sf_success_ns_avg=%.1f sf_success_ns_max=%llu"
            " sf_eagain_calls=%llu sf_eintr_calls=%llu sf_zero_returns=%llu"
            " payload_bytes=%llu workers_hint=%d sndbuf_bytes=%d notsent_lowat_bytes=%d\n",
            mode_str(cfg->mode),
            relpath ? relpath : "-",
            (unsigned long long)st->request_read_calls,
            (unsigned long long)st->request_read_bytes,
            (unsigned long long)st->request_read_ns_total,
            (unsigned long long)st->request_read_ns_max,
            (unsigned long long)st->hdr_write_calls,
            (unsigned long long)st->hdr_write_bytes,
            (unsigned long long)st->hdr_write_ns_total,
            (unsigned long long)st->hdr_write_ns_max,
            (unsigned long long)st->file_read_calls,
            (unsigned long long)st->file_read_bytes,
            (unsigned long long)st->file_read_ns_total,
            (unsigned long long)st->file_read_ns_max,
            (unsigned long long)st->ssl_write_calls,
            (unsigned long long)st->ssl_write_bytes,
            (unsigned long long)st->ssl_write_ns_total,
            (unsigned long long)st->ssl_write_ns_max,
            (unsigned long long)st->sf_calls,
            (unsigned long long)st->sf_bytes,
            (unsigned long long)st->sf_ns_total,
            sf_ns_avg,
            (unsigned long long)st->sf_ns_max,
            (unsigned long long)st->sf_success_calls,
            (unsigned long long)st->sf_success_bytes,
            (unsigned long long)st->sf_success_ns_total,
            sf_success_ns_avg,
            (unsigned long long)st->sf_success_ns_max,
            (unsigned long long)st->sf_eagain_calls,
            (unsigned long long)st->sf_eintr_calls,
            (unsigned long long)st->sf_zero_returns,
            (unsigned long long)st->payload_bytes,
            cfg->workers_hint,
            cfg->sndbuf_bytes,
            cfg->notsent_lowat_bytes);
}

static int handle_one_client(SSL_CTX *ctx, int cfd, const server_cfg_t *cfg) {
    SSL *ssl = NULL;
    int file_fd = -1;
    int rc = -1;
    char req[REQ_BUF_SZ];
    char relpath[PATH_MAX] = "-";
    char fullpath[PATH_MAX];
    struct stat stbuf;
    stats_t st;
    uint64_t measure_begin_ns = 0;
    uint64_t measure_end_ns = 0;

    memset(&st, 0, sizeof(st));

    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    apply_socket_tuning(cfd, cfg);

    if (SSL_set_fd(ssl, cfd) != 1) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    if (SSL_accept(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        goto out;
    }

    fprintf(stderr, "KTLS mode=%s active=%d workers_hint=%d sndbuf_bytes=%d notsent_lowat_bytes=%d\n",
            mode_str(cfg->mode), BIO_get_ktls_send(SSL_get_wbio(ssl)), cfg->workers_hint,
            cfg->sndbuf_bytes, cfg->notsent_lowat_bytes);
    fprintf(stderr, "[conn] accepted, mode=%s, cipher=%s\n",
            mode_str(cfg->mode), SSL_get_cipher(ssl));

    memset(req, 0, sizeof(req));
    if (ssl_read_request(ssl, req, sizeof(req), &st) <= 0) {
        fprintf(stderr, "[conn] failed to read request\n");
        goto out;
    }

    fprintf(stderr, "REQUEST mode=%s raw=\"%.*s\"\n", mode_str(cfg->mode), 120, req);

    if (!parse_http_get_path(req, relpath, sizeof(relpath))) {
        send_http_error(ssl, 400, "Bad Request", "Bad Request\n", &st);
        rc = 0;
        goto out;
    }

    if (!build_full_path(cfg->base_dir, relpath, fullpath, sizeof(fullpath))) {
        send_http_error(ssl, 400, "Bad Request", "Invalid Path\n", &st);
        rc = 0;
        goto out;
    }

    file_fd = open(fullpath, O_RDONLY);
    if (file_fd < 0) {
        send_http_error(ssl, 404, "Not Found", "Not Found\n", &st);
        rc = 0;
        goto out;
    }

    if (fstat(file_fd, &stbuf) < 0) {
        perror("fstat");
        send_http_error(ssl, 500, "Internal Server Error", "fstat failed\n", &st);
        rc = 0;
        goto out;
    }

    if (!S_ISREG(stbuf.st_mode)) {
        send_http_error(ssl, 403, "Forbidden", "Not a regular file\n", &st);
        rc = 0;
        goto out;
    }

    if (send_http_ok_header(ssl, stbuf.st_size, &st) < 0) {
        goto out;
    }

    measure_begin_ns = now_ns();
    fprintf(stderr, "MEASURE_BEGIN mode=%s file=%s bytes=%lld t_ns=%llu\n",
            mode_str(cfg->mode), relpath, (long long)stbuf.st_size,
            (unsigned long long)measure_begin_ns);

    if (cfg->mode == MODE_OPENSSL) {
        fprintf(stderr, "[conn] OPENSSL path: SSL_write()\n");
        if (send_file_openssl(ssl, file_fd, &st) < 0) {
            goto out;
        }
    } else {
        BIO *wbio = SSL_get_wbio(ssl);
        int ktls_send = BIO_get_ktls_send(wbio);

        if (!ktls_send) {
            fprintf(stderr, "[conn] kTLS TX is not active; cannot use raw sendfile safely in %s mode\n",
                    mode_str(cfg->mode));
            goto out;
        }

        fprintf(stderr, "[conn] kTLS TX active\n");

        if (cfg->mode == MODE_HWKTLS) {
            if (enable_hw_ktls_zerocopy_if_possible(cfd) == 0) {
                fprintf(stderr, "[conn] TLS_TX_ZEROCOPY_RO enabled\n");
            } else {
                fprintf(stderr, "[conn] TLS_TX_ZEROCOPY_RO enable failed; continuing\n");
            }
            fprintf(stderr, "[conn] HWKTLS requested; actual NIC offload must be verified externally\n");
        }

        fprintf(stderr, "[conn] %s path: raw sendfile() on socket fd\n", mode_str(cfg->mode));
        if (send_file_sendfile(cfd, file_fd, stbuf.st_size, &st) < 0) {
            goto out;
        }
    }

    measure_end_ns = now_ns();
    fprintf(stderr, "MEASURE_END mode=%s file=%s bytes=%llu t_ns=%llu\n",
            mode_str(cfg->mode), relpath, (unsigned long long)st.payload_bytes,
            (unsigned long long)measure_end_ns);

    print_event_stats(&st, cfg, relpath);
    fprintf(stderr, "COMPLETE mode=%s file=%s payload_bytes=%llu wall_ns=%llu\n",
            mode_str(cfg->mode), relpath,
            (unsigned long long)st.payload_bytes,
            (unsigned long long)(measure_end_ns - measure_begin_ns));

    fprintf(stderr, "[conn] transfer complete: %s (%lld bytes)\n",
            fullpath, (long long)stbuf.st_size);

    rc = 0;

out:
    if (file_fd >= 0) {
        close(file_fd);
    }

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    return rc;
}

int main(int argc, char **argv) {
    server_cfg_t cfg;
    SSL_CTX *ctx = NULL;
    int lfd = -1;

    parse_args(argc, argv, &cfg);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    ctx = create_ssl_ctx(&cfg);
    lfd = create_listen_socket(cfg.port);

    fprintf(stderr,
            "Server started: port=%d mode=%s cert=%s key=%s base_dir=%s workers_hint=%d sndbuf_bytes=%d notsent_lowat_bytes=%d\n",
            cfg.port, mode_str(cfg.mode), cfg.cert_path, cfg.key_path, cfg.base_dir,
            cfg.workers_hint, cfg.sndbuf_bytes, cfg.notsent_lowat_bytes);

    while (!g_stop) {
        struct sockaddr_in cliaddr;
        socklen_t clilen = sizeof(cliaddr);
        char ipbuf[INET_ADDRSTRLEN] = {0};

        int cfd = accept(lfd, (struct sockaddr *)&cliaddr, &clilen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        inet_ntop(AF_INET, &cliaddr.sin_addr, ipbuf, sizeof(ipbuf));
        fprintf(stderr, "[accept] client=%s:%u\n", ipbuf, ntohs(cliaddr.sin_port));

        (void)handle_one_client(ctx, cfd, &cfg);
        close(cfd);

        fprintf(stderr, "[accept] client session closed\n");
    }

    if (lfd >= 0) close(lfd);
    if (ctx) SSL_CTX_free(ctx);

    fprintf(stderr, "Server terminated\n");
    return 0;
}
