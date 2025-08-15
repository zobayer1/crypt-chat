//
// Created by zobayer on 7/17/25.
//
#include "network.h"

#include "crypto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint64_t max_uint64(uint64_t a, uint64_t b) { return a > b ? a : b; }

static void print_and_signal(int fd, const char *sigval, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    fflush(stdout);
    va_end(args);
    write(fd, sigval, 1);
}

static void free_session_keys(UserSession *session) {
    if (!session)
        return;
    if (session->pubkey) {
        free(session->pubkey);
        session->pubkey = NULL;
    }
    if (session->privkey) {
        free(session->privkey);
        session->privkey = NULL;
    }
    if (session->sesskey) {
        free(session->sesskey);
        session->sesskey = NULL;
    }
}

static void set_peer_disconnect_states(NetworkState *net) {
    net->session_active = false;
    net->connection_active = false;
    shutdown(net->active_sock, SHUT_RDWR);
    close(net->active_sock);
    net->active_sock = -1;
    memset(net->remote_peer, 0, sizeof(net->remote_peer));
    free_session_keys(net->remote_session);
    free(net->remote_session);
}

static int send_existing_pubkey(const NetworkState *network, const ProtocolType protocol, uint64_t reply_nonce) {
    if (!network->local_session->pubkey || !network->local_session->privkey) {
        free_session_keys(network->local_session);
        return -1;
    }
    network->local_session->nonce = max_uint64(generate_nonce(), network->local_session->nonce + 1);
    if (network_send(network->active_sock, protocol, NULL, network->local_session, network->local_session->nonce,
                     reply_nonce) < 0) {
        return -1;
    }
    return 0;
}

static int send_new_pubkey(const NetworkState *network, const ProtocolType protocol, uint64_t reply_nonce) {
    free_session_keys(network->local_session);
    network->local_session->pubkey = malloc(RSA2048_PUBKEY_PEM_SIZE);
    network->local_session->privkey = malloc(RSA2048_PRIVKEY_PEM_SIZE);
    if (generate_rsa_keypair(network->local_session->pubkey, RSA2048_PUBKEY_PEM_SIZE - 1,
                             network->local_session->privkey, RSA2048_PRIVKEY_PEM_SIZE - 1) != 0) {
        free_session_keys(network->local_session);
        return -1;
    }
    network->local_session->nonce = max_uint64(generate_nonce(), network->local_session->nonce + 1);
    if (network_send(network->active_sock, protocol, NULL, network->local_session, network->local_session->nonce,
                     reply_nonce) < 0) {
        return -1;
    }
    return 0;
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
            protocol_parse_conn_msg(body, session, &msg_nonce, NULL);
            if (!nonce_within_grace(msg_nonce, curr_nonce)) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Nonce", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Nonce");
                free(session);
                break;
            }
            msg_nonce++;
            net->session_active = true;
            net->remote_session = session;
            net->remote_session->nonce = msg_nonce;
            net->local_session->nonce =
                max_uint64(max_uint64(msg_nonce, net->local_session->nonce + 1), generate_nonce());

            network_send(net->active_sock, PROTOCOL_CONN_ACK, NULL, net->local_session, net->local_session->nonce,
                         msg_nonce);

            uuid_to_str(net->remote_session->sid, uuid_s);
            print_and_signal(net->pipefd[1], "\1", "\nConnected to %s\n%s [%s]\n", net->remote_peer,
                             net->remote_session->username, uuid_s);
            pthread_mutex_unlock(&net->lock);
        } else if (type == PROTOCOL_CONN_ACK) {
            pthread_mutex_lock(&net->lock);
            if (net->session_active) {
                pthread_mutex_unlock(&net->lock);
                continue;
            }

            UserSession *session = malloc(sizeof(UserSession));
            memset(session, 0, sizeof(UserSession));
            uint64_t msg_nonce = 0, reply_nonce = 0;
            protocol_parse_conn_msg(body, session, &msg_nonce, &reply_nonce);
            if (reply_nonce - 1 != net->local_session->nonce) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Nonce", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Nonce");
                free(session);
                break;
            }

            net->session_active = true;
            net->remote_session = session;
            net->remote_session->nonce = msg_nonce;
            net->local_session->nonce = max_uint64(generate_nonce(), max_uint64(reply_nonce, msg_nonce));

            uuid_to_str(net->remote_session->sid, uuid_s);
            print_and_signal(net->pipefd[1], "\1", "\nConnected to %s\n%s [%s]\n", net->remote_peer,
                             net->remote_session->username, uuid_s);
            pthread_mutex_unlock(&net->lock);
        } else if (type == PROTOCOL_MSG) {
            pthread_mutex_lock(&net->lock);
            if (!net->session_active) {
                pthread_mutex_unlock(&net->lock);
                continue;
            }
            char msg[PROTOCOL_MSG_MAX_LEN] = {0};
            if (protocol_parse_plain_msg(body, msg, sizeof(msg)) > 0) {
                print_and_signal(net->pipefd[1], "\1", "\n[%s]> %s\n", net->remote_session->username, msg);
            }
            pthread_mutex_unlock(&net->lock);
        } else if (type == PROTOCOL_PKEY_OFFER) {
            pthread_mutex_lock(&net->lock);
            if (!net->session_active) {
                pthread_mutex_unlock(&net->lock);
                continue;
            }
            uuid_t remote_id;
            uint64_t msg_nonce = 0;
            char pubkey[RSA2048_PUBKEY_PEM_SIZE] = {0};
            char sig_b64[RSA2048_SIG_PEM_SIZE] = {0};
            unsigned char sig[RSA2048_SIG_PEM_SIZE] = {0};
            int parsed = protocol_parse_pkey_msg(body, &remote_id, &msg_nonce, NULL, pubkey,
                                                 RSA2048_PUBKEY_PEM_SIZE - 1, sig_b64, RSA2048_SIG_PEM_SIZE - 1);
            if (parsed < 0 || uuid_is_null(remote_id) || msg_nonce == 0 || !pubkey[0] || !sig_b64[0]) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Public Key Offer", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Public Key Offer");
                break;
            }
            if (msg_nonce <= net->remote_session->nonce) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Nonce", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Nonce");
                break;
            }
            if (base64_decode(sig_b64, strlen(sig_b64), sig, sizeof(sig)) < 0) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Signature Format", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Signature Format");
                break;
            }
            unsigned char sig_msg[SESSION_ID_LEN + RSA2048_PUBKEY_PEM_SIZE + SESSION_NONCE_LEN] = {0};
            uuid_to_str(remote_id, uuid_s);
            size_t sig_msg_len = snprintf((char *)sig_msg, sizeof(sig_msg), "%s%s%" PRIu64, pubkey, uuid_s, msg_nonce);
            if (rsa_verify_signature(pubkey, sig_msg, sig_msg_len, sig, 256) != 0) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Signature Verification Failed", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Signature Verification Failed");
                break;
            }
            printf("\nReceived public key from %s\n%s", net->remote_session->username, pubkey);
            msg_nonce++;
            free_session_keys(net->remote_session);
            net->remote_session->pubkey = malloc(RSA2048_PUBKEY_PEM_SIZE);
            strcpy(net->remote_session->pubkey, pubkey);

            net->remote_session->nonce = msg_nonce;
            net->local_session->nonce =
                max_uint64(max_uint64(msg_nonce, net->local_session->nonce + 1), generate_nonce());
            int pkey_sent = 0;
            if (net->local_session->pubkey && net->local_session->privkey) {
                pkey_sent = send_existing_pubkey(net, PROTOCOL_PKEY_RESP, msg_nonce);
            } else {
                pkey_sent = send_new_pubkey(net, PROTOCOL_PKEY_RESP, msg_nonce);
            }
            if (pkey_sent < 0) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Public Key Exchange Failed", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Failed to send public key");
                break;
            }
            print_and_signal(net->pipefd[1], "\1", "Pubkey exchange complete\n%s", net->local_session->pubkey);
            pthread_mutex_unlock(&net->lock);
        } else if (type == PROTOCOL_PKEY_RESP) {
            pthread_mutex_lock(&net->lock);
            if (!net->session_active) {
                pthread_mutex_unlock(&net->lock);
                continue;
            }
            uuid_t remote_id;
            uint64_t msg_nonce = 0, reply_nonce = 0;
            char pubkey[RSA2048_PUBKEY_PEM_SIZE] = {0};
            char sig_b64[RSA2048_SIG_PEM_SIZE] = {0};
            unsigned char sig[RSA2048_SIG_PEM_SIZE] = {0};
            int parsed = protocol_parse_pkey_msg(body, &remote_id, &msg_nonce, &reply_nonce, pubkey,
                                                 RSA2048_PUBKEY_PEM_SIZE - 1, sig_b64, RSA2048_SIG_PEM_SIZE - 1);
            if (parsed < 0 || uuid_is_null(remote_id) || msg_nonce == 0 || reply_nonce == 0 || !pubkey[0] ||
                !sig_b64[0]) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Public Key Response", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Public Key Response");
                break;
            }
            if (reply_nonce - 1 != net->local_session->nonce) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Nonce", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Nonce");
                break;
            }
            if (base64_decode(sig_b64, strlen(sig_b64), sig, sizeof(sig)) < 0) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Bad Signature Format", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Bad Signature Format");
                break;
            }
            unsigned char sig_msg[SESSION_ID_LEN + RSA2048_PUBKEY_PEM_SIZE + 2 * SESSION_NONCE_LEN] = {0};
            uuid_to_str(remote_id, uuid_s);
            size_t sig_msg_len = snprintf((char *)sig_msg, sizeof(sig_msg), "%s%s%" PRIu64 "%" PRIu64, pubkey, uuid_s,
                                          msg_nonce, reply_nonce);
            if (rsa_verify_signature(pubkey, sig_msg, sig_msg_len, sig, 256) != 0) {
                network_send(net->active_sock, PROTOCOL_REJECT, "Signature Verification Failed", NULL, 0, 0);
                pthread_mutex_unlock(&net->lock);
                strcpy(reason, "Signature Verification Failed");
                break;
            }
            printf("\nReceived public key from %s\n%s", net->remote_session->username, pubkey);
            free_session_keys(net->remote_session);
            net->remote_session->pubkey = malloc(RSA2048_PUBKEY_PEM_SIZE);
            strcpy(net->remote_session->pubkey, pubkey);

            net->remote_session->nonce = msg_nonce;
            net->local_session->nonce = max_uint64(generate_nonce(), max_uint64(reply_nonce, msg_nonce));
            pthread_mutex_unlock(&net->lock);
            print_and_signal(net->pipefd[1], "\1", "Pubkey exchange complete\n");
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
            network_send(client_sock, PROTOCOL_REJECT, "Peer Busy", NULL, 0, 0);
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
    net->local_session->nonce = nonce > net->local_session->nonce ? nonce : net->local_session->nonce + 1;
    network_send(net->active_sock, PROTOCOL_CONN, NULL, net->local_session, net->local_session->nonce, 0);
    pthread_mutex_unlock(&net->lock);
    return 0; // Success
}

ssize_t network_send(const int sock, const ProtocolType type, const char *payload, const UserSession *session,
                     const uint64_t nonce, const uint64_t reply_nonce) {
    if (sock < 0)
        return -1;
    char msg[PROTOCOL_MSG_MAX_LEN] = {0};
    size_t len = 0;
    if (type == PROTOCOL_CONN && session) {
        len = protocol_prepare_conn_msg(msg, sizeof(msg), session, nonce);
    } else if (type == PROTOCOL_CONN_ACK && session) {
        len = protocol_prepare_conn_ack_msg(msg, sizeof(msg), session, nonce, reply_nonce);
    } else if (type == PROTOCOL_PKEY_OFFER && session) {
        unsigned char data[SESSION_ID_LEN + RSA2048_PUBKEY_PEM_SIZE + SESSION_NONCE_LEN] = {0};
        char uuid_s[SESSION_ID_LEN] = {0};
        uuid_to_str(session->sid, uuid_s);
        size_t data_len = snprintf((char *)data, sizeof(data), "%s%s%" PRIu64, session->pubkey, uuid_s, nonce);
        unsigned char *sig = NULL;
        size_t sig_len = 0;
        if (rsa_sign_message(session->privkey, data, data_len, &sig, &sig_len) != 0) {
            if (sig)
                free(sig);
            return -1;
        }
        char sig_b64[RSA2048_SIG_PEM_SIZE] = {0};
        if (base64_encode(sig, sig_len, sig_b64, sizeof(sig_b64)) < 0) {
            if (sig)
                free(sig);
            return -1;
        }
        len = protocol_prepare_pkey_offer_msg(msg, sizeof(msg), session, nonce, sig_b64);
        if (sig)
            free(sig);
    } else if (type == PROTOCOL_PKEY_RESP && session) {
        unsigned char data[SESSION_ID_LEN + RSA2048_PUBKEY_PEM_SIZE + 2 * SESSION_NONCE_LEN] = {0};
        char uuid_s[SESSION_ID_LEN] = {0};
        uuid_to_str(session->sid, uuid_s);
        size_t data_len = snprintf((char *)data, sizeof(data), "%s%s%" PRIu64 "%" PRIu64, session->pubkey, uuid_s,
                                   nonce, reply_nonce);
        unsigned char *sig = NULL;
        size_t sig_len = 0;
        if (rsa_sign_message(session->privkey, data, data_len, &sig, &sig_len) != 0) {
            if (sig)
                free(sig);
            return -1;
        }
        char sig_b64[RSA2048_SIG_PEM_SIZE] = {0};
        if (base64_encode(sig, sig_len, sig_b64, sizeof(sig_b64)) < 0) {
            if (sig)
                free(sig);
            return -1;
        }
        len = protocol_prepare_pkey_resp_msg(msg, sizeof(msg), session, nonce, reply_nonce, sig_b64);
        if (sig)
            free(sig);
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
    network_send(net->active_sock, PROTOCOL_BYE, "Peer Left", NULL, 0, 0);
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
    free_session_keys(net->local_session);
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
    } else if (strncmp(command, ":exchange ", 10) == 0) {
        pthread_mutex_lock(&network->lock);
        if (!network->session_active) {
            printf("Error: No active connection\n");
            pthread_mutex_unlock(&network->lock);
            return;
        }
        char k_type[16], k_fresh[16] = {0};
        if (sscanf(command + 10, "%15s %15s", k_type, k_fresh) < 1) {
            printf("Invalid command format. Use: :exchange {keytype=pub|session} [{freshness=new}]\n");
        } else if (!strcmp(k_type, "pub")) {
            int pkey_sent = 0;
            if (network->local_session->pubkey && network->local_session->privkey && strcmp(k_fresh, "new") != 0) {
                pkey_sent = send_existing_pubkey(network, PROTOCOL_PKEY_OFFER, 0);
            } else {
                pkey_sent = send_new_pubkey(network, PROTOCOL_PKEY_OFFER, 0);
            }
            if (pkey_sent < 0) {
                printf("Error: Failed to send public key\n");
            } else {
                printf("Public key exchange initiated\n%s", network->local_session->pubkey);
            }
        } else {
            printf("Error: Unsupported key type '%s'\n", k_type);
        }
        pthread_mutex_unlock(&network->lock);
    } else {
        pthread_mutex_lock(&network->lock);
        if (!network->session_active) {
            printf("Error: No active connection\n");
        } else {
            network_send(network->active_sock, PROTOCOL_MSG, command, NULL, 0, 0);
        }
        pthread_mutex_unlock(&network->lock);
    }
}
