//
// Created by zobayer on 7/17/25.
//
#ifndef NETWORK_H
#define NETWORK_H

#include "protocol.h"
#include "session.h"

#include <pthread.h>
#include <stdbool.h>

typedef struct {
    int host_port;
    int active_sock;
    int listen_sock;
    int pipefd[2];
    char remote_peer[256];
    bool listening;
    bool connection_active;
    bool session_active;
    pthread_t listener_thread;
    pthread_t message_thread;
    pthread_mutex_t lock;
    UserSession *local_session;
    UserSession *remote_session;
} NetworkState;

NetworkState *network_init(UserSession *local_session, int port);

int network_connect(NetworkState *net, const char *host, int port);

void network_command(NetworkState *network, const char *command);

ssize_t network_send(int sock, ProtocolType type, const char *payload, const UserSession *session,
                     const UserSession *remote_session, uint64_t reply_nonce);

int network_disconnect(NetworkState *net);

void network_stop(NetworkState *net);

#endif // NETWORK_H
