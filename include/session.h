//
// Created by zobayer on 7/17/25.
//
#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <uuid/uuid.h>

#define USERNAME_MAX_LEN 64
#define SESSION_ID_LEN 37
#define SESSION_NONCE_LEN 32

typedef struct {
    uuid_t sid;
    char username[USERNAME_MAX_LEN];
    uint64_t nonce;
    char *pubkey;
    char *privkey;
    unsigned char *sesskey;
} UserSession;

UserSession *session_init(void);

#endif // SESSION_H
