//
// Created by zobayer on 7/17/25.
//
#include "network.h"

#include "crypto.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void print_and_signal(int fd, const char *sigval, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    fflush(stdout);
    va_end(args);
    write(fd, sigval, 1);
}

static void set_peer_disconnect_states(NetworkState *net) {
    net->session_active = false;
    net->connection_active = false;
    shutdown(net->active_sock, SHUT_RDWR);
    close(net->active_sock);
    net->active_sock = -1;
    memset(net->remote_peer, 0, sizeof(net->remote_peer));
    free(net->remote_session);
}

static void *message_callback(void *arg) {
    NetworkState *net = arg;
    char buffer[PROTOCOL_MSG_MAX_LEN] = {0};
    char body[PROTOCOL_MSG_MAX_LEN] = {0};
    char reason[PROTOCOL_DC_MSG_MAX_LEN] = {0};
    char uuid_s[SESSION_ID_LEN] = {0};
    while (recv(net->active_sock, buffer, sizeof(buffer) - 1, 0) > 0) {
        ProtocolType type = protocol_parse_message(buffer, body, sizeof(body));
        if (type == PROTOCOL_BYE || type == PROTOCOL_REJECT) {
            protocol_parse_dc_msg(body, reason, sizeof(reason));
            break;
        }
        if (type == PROTOCOL_CONN) {
            pthread_mutex_lock(&net->lock);
            if (net->session_active) {
                pthread_mutex_unlock(&net->lock);
                continue;
            }

            UserSession *session = malloc(sizeof(UserSession));
            memset(session, 0, sizeof(UserSession));
            uint64_t msg_nonce = 0;
            uint64_t curr_nonce = generate_nonce();
            protocol_parse_conn_msg(body, session, &msg_nonce);
            if (!nonce_within_grace(msg_nonce, curr_nonce)) {
                pthread_mutex_unlock(&net->lock);
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Nonce", NULL, 0);
                strcpy(reason, "Bad Nonce");
                free(session);
                break;
            }

            msg_nonce++;
            net->session_active = true;
            net->remote_session = session;
            net->remote_session->nonce = msg_nonce;
            net->local_session->nonce = msg_nonce;
            pthread_mutex_unlock(&net->lock);

            network_send(net->active_sock, PROTOCOL_CONN_ACK, NULL, net->local_session, msg_nonce);

            uuid_str(net->remote_session->sid, uuid_s);
            print_and_signal(net->pipefd[1], "\1", "\nConnected to %s\n%s [%s]\n", net->remote_peer,
                             net->remote_session->username, uuid_s);
        } else if (type == PROTOCOL_CONN_ACK) {
            pthread_mutex_lock(&net->lock);
            if (net->session_active) {
                pthread_mutex_unlock(&net->lock);
                continue;
            }

            UserSession *session = malloc(sizeof(UserSession));
            memset(session, 0, sizeof(UserSession));
            uint64_t msg_nonce = 0;
            protocol_parse_conn_msg(body, session, &msg_nonce);
            if (msg_nonce - 1 != net->local_session->nonce) {
                pthread_mutex_unlock(&net->lock);
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Nonce", NULL, 0);
                strcpy(reason, "Bad Nonce");
                free(session);
                break;
            }

            net->session_active = true;
            net->remote_session = session;
            net->remote_session->nonce = msg_nonce;
            net->local_session->nonce = msg_nonce;
            pthread_mutex_unlock(&net->lock);

            uuid_str(net->remote_session->sid, uuid_s);
            print_and_signal(net->pipefd[1], "\1", "\nConnected to %s\n%s [%s]\n", net->remote_peer,
                             net->remote_session->username, uuid_s);
        } else if (type == PROTOCOL_MSG) {
            if (!net->session_active)
                continue;
            char msg[PROTOCOL_MSG_MAX_LEN] = {0};
            if (protocol_parse_plain_msg(body, msg, sizeof(msg)) > 0) {
                print_and_signal(net->pipefd[1], "\1", "\n[%s]> %s\n", net->remote_session->username, msg);
            }
        }
        memset(buffer, 0, sizeof buffer);
    }
    pthread_mutex_lock(&net->lock);
    if (net->connection_active) {
        print_and_signal(net->pipefd[1], "\1", "\nDisconnected: %s\n", reason[0] ? reason : "Peer Left");
    }
    set_peer_disconnect_states(net);
    pthread_mutex_unlock(&net->lock);
    return NULL;
}

static void *listener_callback(void *arg) {
    NetworkState *net = arg;
    while (net->listening) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(net->listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock == -1)
            break;
        pthread_mutex_lock(&net->lock);
        if (net->connection_active) {
            network_send(client_sock, PROTOCOL_REJECT, "Peer Busy", NULL, 0);
            close(client_sock);
        } else {
            net->active_sock = client_sock;
            net->connection_active = true;
            net->session_active = false;
            inet_ntop(AF_INET, &client_addr.sin_addr, net->remote_peer, sizeof(net->remote_peer));
            pthread_create(&net->message_thread, NULL, message_callback, net);
        }
        pthread_mutex_unlock(&net->lock);
    }
    return NULL;
}

NetworkState *network_init(UserSession *local_session, int port) {
    NetworkState *network = malloc(sizeof(NetworkState));
    memset(network, 0, sizeof(NetworkState));
    network->host_port = port;
    network->local_session = local_session;
    pthread_mutex_init(&network->lock, NULL);
    if (pipe(network->pipefd) != 0) {
        fprintf(stderr, "Error initializing pipe\n");
        free(network);
        exit(EXIT_FAILURE);
    }

    pthread_mutex_lock(&network->lock);
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET, .sin_port = htons(network->host_port), .sin_addr.s_addr = INADDR_ANY};

    network->listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (network->listen_sock < 0) {
        fprintf(stderr, "Error creating socket\n");
        pthread_mutex_unlock(&network->lock);
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(network->listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        fprintf(stderr, "Error setting socket options\n");
        close(network->listen_sock);
        pthread_mutex_unlock(&network->lock);
        exit(EXIT_FAILURE);
    }

    if (bind(network->listen_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        if (errno == EADDRINUSE) {
            fprintf(stderr, "Port %d already in use\n", network->host_port);
        } else {
            fprintf(stderr, "Error binding socket address\n");
        }
        pthread_mutex_unlock(&network->lock);
        exit(EXIT_FAILURE);
    }

    if (listen(network->listen_sock, 1) != 0) {
        fprintf(stderr, "Error listening on socket\n");
        close(network->listen_sock);
        pthread_mutex_unlock(&network->lock);
        exit(EXIT_FAILURE);
    }

    network->listening = true;
    pthread_create(&network->listener_thread, NULL, listener_callback, network);
    pthread_mutex_unlock(&network->lock);
    print_and_signal(network->pipefd[1], "\1", "Listening on port %d\n", network->host_port);

    return network;
}

int network_connect(NetworkState *net, const char *host, int port) {
    pthread_mutex_lock(&net->lock);
    if (net->connection_active) {
        pthread_mutex_unlock(&net->lock);
        return -1; // Already connected
    }

    if ((strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0) && port == net->host_port) {
        pthread_mutex_unlock(&net->lock);
        return -2; // Attempt to connect to self
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {.sin_family = AF_INET, .sin_port = htons(port)};

    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        close(sock);
        pthread_mutex_unlock(&net->lock);
        return -3; // Invalid host address
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        pthread_mutex_unlock(&net->lock);
        return -4; // Connection failed
    }

    net->connection_active = true;
    net->session_active = false;
    net->active_sock = sock;
    strncpy(net->remote_peer, host, sizeof(net->remote_peer));

    pthread_create(&net->message_thread, NULL, message_callback, net);

    uint64_t nonce = generate_nonce();
    net->local_session->nonce = nonce;
    network_send(net->active_sock, PROTOCOL_CONN, NULL, net->local_session, nonce);
    pthread_mutex_unlock(&net->lock);
    return 0; // Success
}

ssize_t network_send(int sock, ProtocolType type, const char *payload, const UserSession *session, uint64_t nonce) {
    if (sock < 0)
        return 0;
    char msg[PROTOCOL_MSG_MAX_LEN] = {0};
    size_t len = 0;
    if (type == PROTOCOL_CONN && session) {
        len = protocol_prepare_conn_msg(msg, sizeof(msg), session, nonce);
    } else if (type == PROTOCOL_CONN_ACK && session) {
        len = protocol_prepare_conn_ack_msg(msg, sizeof(msg), session, nonce);
    } else if (type == PROTOCOL_MSG && payload) {
        len = protocol_prepare_plain_msg(msg, sizeof(msg), payload);
    } else if (type == PROTOCOL_BYE || type == PROTOCOL_REJECT) {
        len = protocol_prepare_dc_msg(msg, sizeof(msg), type, payload);
    } else {
        return -1;
    }
    return send(sock, msg, len, 0);
}

int network_disconnect(NetworkState *net) {
    pthread_mutex_lock(&net->lock);
    if (!net->connection_active) {
        pthread_mutex_unlock(&net->lock);
        return -1; // No active connection
    }
    network_send(net->active_sock, PROTOCOL_BYE, "Peer Left", NULL, 0);
    set_peer_disconnect_states(net);
    pthread_mutex_unlock(&net->lock);
    pthread_join(net->message_thread, NULL);
    return 0; // Success
}

void network_stop(NetworkState *net) {
    printf("Stopping listener thread...\n");
    net->listening = false;
    shutdown(net->listen_sock, SHUT_RDWR);
    close(net->listen_sock);
    pthread_join(net->listener_thread, NULL);
    printf("Listener thread stopped\n");
    if (net->connection_active) {
        printf("Closing active connection...\n");
        pthread_mutex_lock(&net->lock);
        set_peer_disconnect_states(net);
        pthread_mutex_unlock(&net->lock);
        pthread_join(net->message_thread, NULL);
        printf("Active connection closed\n");
    }
    pthread_mutex_destroy(&net->lock);
    free(net->local_session);
    free(net);
}

void network_command(NetworkState *network, const char *command) {
    if (strncmp(command, ":connect ", 9) == 0) {
        char host[256], port_s[16];
        if (sscanf(command + 9, "%255[^:]:%s", host, port_s) != 2) {
            printf("Invalid host format. Use: :connect host:port\n");
        } else {
            const int port = (int)strtol(port_s, NULL, 10);
            const int sock = network_connect(network, host, port);
            if (sock >= 0) {
                printf("Connecting to %s:%d\n", host, port);
            } else if (sock == -1) {
                printf("Error: Already connected to another peer %s\n", network->remote_peer);
            } else if (sock == -2) {
                printf("Error: Attempt to connect to self (%s:%d)\n", host, port);
            } else if (sock == -3) {
                printf("Error: Invalid host address (%s:%d)\n", host, port);
            } else {
                printf("Error: Connection failed to (%s:%d)\n", host, port);
            }
        }
    } else if (strcmp(command, ":disconnect\n") == 0) {
        if (network_disconnect(network)) {
            printf("Error: No active connection\n");
        } else {
            printf("Connection closed\n");
        }
    } else {
        pthread_mutex_lock(&network->lock);
        if (!network->session_active) {
            printf("Error: No active connection\n");
        } else {
            network_send(network->active_sock, PROTOCOL_MSG, command, NULL, 0);
        }
        pthread_mutex_unlock(&network->lock);
    }
}
