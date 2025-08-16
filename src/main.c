//
// Created by zobayer on 7/17/25.
//
#include "network.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_COMMAND_LEN 2048

int main(const int argc, const char **argv) {
    int port = 12345;
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s [PORT]\n", argv[0]);
        return EXIT_SUCCESS;
    }
    if (argc > 1) {
        port = (int)strtol(argv[1], NULL, 10);
        if (errno || port < 1024 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    }

    UserSession *session = session_init();
    NetworkState *network = network_init(session, port);

    fd_set readfds;
    char buffer[MAX_COMMAND_LEN] = {0};
    int maxfd = (network->pipefd[0] > fileno(stdin)) ? network->pipefd[0] : fileno(stdin);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(fileno(stdin), &readfds);
        FD_SET(network->pipefd[0], &readfds);
        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            break;
        }
        if (FD_ISSET(network->pipefd[0], &readfds)) {
            char signal_buf[8];
            read(network->pipefd[0], signal_buf, sizeof(signal_buf));
            int is_e2e = network->session_active && network->remote_session->sesskey;
            printf("[%s]%s> ", network->local_session->username, is_e2e ? "*" : "");
            fflush(stdout);
        }
        if (FD_ISSET(fileno(stdin), &readfds)) {
            if (!fgets(buffer, sizeof buffer, stdin) || !strcmp(buffer, ":quit\n")) {
                break;
            }
            network_command(network, buffer);
            memset(buffer, 0, sizeof(buffer));
            int is_e2e = network->session_active && network->remote_session->sesskey;
            printf("[%s]%s> ", network->local_session->username, is_e2e ? "*" : "");
            fflush(stdout);
        }
    }

    network_stop(network);
    printf("Goodbye!\n");
    return EXIT_SUCCESS;
}
