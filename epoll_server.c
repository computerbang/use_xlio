// xlio_basic_server.c
// 일반 POSIX TCP 서버 예제
// 실행할 때 LD_PRELOAD=libxlio.so 를 붙이면 XLIO가 socket/send/recv 등을 가로채 가속

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 9090
#define BACKLOG 128
#define BUF_SIZE 4096

int main(void) {
    int listen_fd, conn_fd;
    struct sockaddr_in srv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char buf[BUF_SIZE];

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listen_fd);
        return 1;
    }

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = INADDR_ANY;
    srv_addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("Server listening on port %d\n", PORT);

    while (1) {
        conn_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (conn_fd < 0) {
            perror("accept");
            continue;
        }

        printf("Client connected: %s:%d\n",
               inet_ntoa(cli_addr.sin_addr),
               ntohs(cli_addr.sin_port));

        while (1) {
            ssize_t n = recv(conn_fd, buf, sizeof(buf), 0);
            if (n < 0) {
                perror("recv");
                break;
            }
            if (n == 0) {
                printf("Client disconnected\n");
                break;
            }

            // 받은 데이터 그대로 다시 전송 (echo)
            ssize_t sent = send(conn_fd, buf, n, 0);
            if (sent < 0) {
                perror("send");
                break;
            }
        }

        close(conn_fd);
    }

    close(listen_fd);
    return 0;
}
