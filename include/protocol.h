//
// Created by zobayer on 7/17/25.
//
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "session.h"

#include <stdint.h>

#define PROTOCOL_MSG_MAX_LEN 4096
#define PROTOCOL_DC_MSG_MAX_LEN 256

typedef enum {
    PROTOCOL_CONN,
    PROTOCOL_CONN_ACK,
    PROTOCOL_BYE,
    PROTOCOL_REJECT,
    PROTOCOL_MSG,
    PROTOCOL_CIPHER,
    PROTOCOL_PUBKEY_OFFER,
    PROTOCOL_PUBKEY_RESP,
    PROTOCOL_SESSKEY_OFFER,
    PROTOCOL_SESSKEY_RESP,
    PROTOCOL_ERROR
} ProtocolType;

size_t protocol_prepare_conn_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce);

size_t protocol_prepare_conn_ack_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                     uint64_t reply_nonce);

int protocol_parse_conn_msg(const char *msg, UserSession *session, uint64_t *nonce, uint64_t *reply_nonce);

size_t protocol_prepare_plain_msg(char *buffer, size_t buf_len, const char *message);

int protocol_parse_plain_msg(const char *msg, char *body, size_t body_len);

size_t protocol_prepare_dc_msg(char *buffer, size_t buf_len, ProtocolType type, const char *reason);

int protocol_parse_dc_msg(const char *msg, char *reason, size_t reason_len);

size_t protocol_prepare_pkey_offer_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                       const char *signature);

size_t protocol_prepare_pkey_resp_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                      uint64_t reply_nonce, const char *signature);

int protocol_parse_pkey_msg(const char *msg, uuid_t *id, uint64_t *nonce, uint64_t *reply_nonce, char *pubkey,
                            size_t pubkey_len, char *sig, size_t sig_len);

size_t protocol_prepare_sesskey_offer_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                          const char *aeskey_b64, const char *sig_b64);

size_t protocol_prepare_sesskey_resp_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                         uint64_t reply_nonce, const char *sig_b64);

int protocol_parse_sesskey_msg(const char *msg, uuid_t *id, uint64_t *nonce, uint64_t *reply_nonce, char *aeskey_b64,
                               size_t aeskey_b64_len, char *sig_b64, size_t sig_b64_len);

ProtocolType protocol_parse_message(const char *msg, char *body, size_t body_len);

#endif // PROTOCOL_H
