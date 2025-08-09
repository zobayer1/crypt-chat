//
// Created by zobayer on 8/9/25.
//
#include "session.h"

#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

UserSession *session_init() {
    UserSession *local_session = malloc(sizeof(UserSession));
    memset(local_session, 0, sizeof(UserSession));

    printf("Enter your username: ");
    fflush(stdout);

    if (fgets(local_session->username, sizeof(local_session->username), stdin) != NULL) {
        local_session->username[strcspn(local_session->username, "\n")] = '\0';
    } else {
        strncpy(local_session->username, "anonymous", sizeof(local_session->username));
    }

    uuid_random(&local_session->sid);

    char uuid_s[SESSION_ID_LEN];
    uuid_str(local_session->sid, uuid_s);
    printf("Welcome, %s!\nSession ID: [%s]\n", local_session->username, uuid_s);

    local_session->nonce = generate_nonce();

    return local_session;
}
