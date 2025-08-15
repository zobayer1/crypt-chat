//
// Created by zobayer on 7/17/25.
//
#include "protocol.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

static const char *protocol_type_to_str(ProtocolType type) {
    switch (type) {
    case PROTOCOL_CONN:
        return "CONN";
    case PROTOCOL_CONN_ACK:
        return "CONN_ACK";
    case PROTOCOL_BYE:
        return "BYE";
    case PROTOCOL_REJECT:
        return "REJECT";
    case PROTOCOL_MSG:
        return "MSG";
    case PROTOCOL_PKEY_OFFER:
        return "PKEY_OFFER";
    case PROTOCOL_PKEY_RESP:
        return "PKEY_RESP";
    case PROTOCOL_ERROR:
    default:
        return "ERROR";
    }
}

static ProtocolType protocol_str_to_type(const char *type_str, size_t type_len) {
    if (type_len == 3 && strncmp(type_str, "BYE", 3) == 0)
        return PROTOCOL_BYE;
    if (type_len == 6 && strncmp(type_str, "REJECT", 6) == 0)
        return PROTOCOL_REJECT;
    if (type_len == 5 && strncmp(type_str, "ERROR", 5) == 0)
        return PROTOCOL_ERROR;
    if (type_len == 8 && strncmp(type_str, "CONN_ACK", 8) == 0)
        return PROTOCOL_CONN_ACK;
    if (type_len == 4 && strncmp(type_str, "CONN", 4) == 0)
        return PROTOCOL_CONN;
    if (type_len == 3 && strncmp(type_str, "MSG", 3) == 0)
        return PROTOCOL_MSG;
    if (type_len == 10 && strncmp(type_str, "PKEY_OFFER", 10) == 0)
        return PROTOCOL_PKEY_OFFER;
    if (type_len == 9 && strncmp(type_str, "PKEY_RESP", 9) == 0)
        return PROTOCOL_PKEY_RESP;
    return PROTOCOL_ERROR;
}

size_t protocol_prepare_conn_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce) {
    char uuid_str[SESSION_ID_LEN];
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len, "TYPE:%s\nID:%s\nNAME:%s\nNONCE:%" PRIu64 "\nEND\n",
                    protocol_type_to_str(PROTOCOL_CONN), uuid_str, session->username, nonce);
}

size_t protocol_prepare_conn_ack_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                     uint64_t reply_nonce) {
    char uuid_str[SESSION_ID_LEN];
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len, "TYPE:%s\nID:%s\nNAME:%s\nNONCE:%" PRIu64 "\nREPLY_NONCE:%" PRIu64 "\nEND\n",
                    protocol_type_to_str(PROTOCOL_CONN_ACK), uuid_str, session->username, nonce, reply_nonce);
}

size_t protocol_parse_conn_msg(const char *msg, UserSession *session, uint64_t *nonce, uint64_t *reply_nonce) {
    char uuid_str[SESSION_ID_LEN] = {0};
    char name[USERNAME_MAX_LEN] = {0};
    char nonce_str[SESSION_NONCE_LEN] = {0};
    const char *id_line = strstr(msg, "ID:");
    const char *name_line = strstr(msg, "NAME:");
    const char *nonce_line = strstr(msg, "NONCE:");
    if (!id_line || !name_line || !nonce_line)
        return -1;
    sscanf(id_line, "ID:%36s", uuid_str);
    sscanf(name_line, "NAME:%63s", name);
    sscanf(nonce_line, "NONCE:%31s", nonce_str);
    uuid_parse(uuid_str, session->sid);
    strncpy(session->username, name, USERNAME_MAX_LEN);
    session->username[USERNAME_MAX_LEN - 1] = '\0';
    *nonce = strtoull(nonce_str, NULL, 10);
    session->nonce = *nonce;
    if (reply_nonce) {
        const char *reply_nonce_line = strstr(msg, "REPLY_NONCE:");
        if (reply_nonce_line) {
            char reply_nonce_str[SESSION_NONCE_LEN] = {0};
            sscanf(reply_nonce_line, "REPLY_NONCE:%31s", reply_nonce_str);
            *reply_nonce = strtoull(reply_nonce_str, NULL, 10);
        } else {
            *reply_nonce = 0;
        }
    }
    return strlen(msg);
}

size_t protocol_prepare_dc_msg(char *buffer, size_t buf_len, ProtocolType type, const char *reason) {
    const char *type_str = protocol_type_to_str(type);
    if (reason && strlen(reason) > 0) {
        return snprintf(buffer, buf_len, "TYPE:%s\nREASON:%s\nEND\n", type_str, reason);
    }
    return snprintf(buffer, buf_len, "TYPE:%s\nEND\n", type_str);
}

size_t protocol_parse_dc_msg(const char *msg, char *reason, size_t reason_len) {
    const char *reason_line = strstr(msg, "REASON:");
    if (!reason_line) {
        reason[0] = '\0';
        return 0;
    }
    const char *reason_start = reason_line + 7;
    const char *reason_end = strchr(reason_start, '\n');
    size_t len = reason_end ? (size_t)(reason_end - reason_start) : strlen(reason_start);
    if (len >= reason_len)
        len = reason_len - 1;
    strncpy(reason, reason_start, len);
    reason[len] = '\0';
    return len;
}

size_t protocol_prepare_pkey_offer_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                       const char *signature) {
    char uuid_str[SESSION_ID_LEN];
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len, "TYPE:%s\nID:%s\nNONCE:%" PRIu64 "\nPUBKEY:%s\nSIG:%s\nEND\n",
                    protocol_type_to_str(PROTOCOL_PKEY_OFFER), uuid_str, nonce, session->pubkey ? session->pubkey : "",
                    signature ? signature : "");
}

size_t protocol_prepare_pkey_resp_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                      uint64_t reply_nonce, const char *signature) {
    char uuid_str[SESSION_ID_LEN];
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len,
                    "TYPE:%s\nID:%s\nNONCE:%" PRIu64 "\nREPLY_NONCE:%" PRIu64 "\nPUBKEY:%s\nSIG:%s\nEND\n",
                    protocol_type_to_str(PROTOCOL_PKEY_RESP), uuid_str, nonce, reply_nonce,
                    session->pubkey ? session->pubkey : "", signature ? signature : "");
}

int protocol_parse_pkey_msg(const char *msg, uuid_t *id, uint64_t *nonce, uint64_t *reply_nonce, char *pubkey,
                            size_t pubkey_len, char *sig, size_t sig_len) {
    char uuid_str[SESSION_ID_LEN] = {0};
    const char *id_line = strstr(msg, "ID:");
    const char *nonce_line = strstr(msg, "NONCE:");
    const char *pubkey_line = strstr(msg, "PUBKEY:");
    const char *sig_line = strstr(msg, "SIG:");
    if (!id_line || !nonce_line || !pubkey_line || !sig_line)
        return -1;
    // ID
    sscanf(id_line, "ID:%36s", uuid_str);
    uuid_parse(uuid_str, *id);
    // NONCE
    char nonce_str[SESSION_NONCE_LEN] = {0};
    sscanf(nonce_line, "NONCE:%31s", nonce_str);
    *nonce = strtoull(nonce_str, NULL, 10);
    // Optional REPLY_NONCE
    if (reply_nonce) {
        const char *reply_nonce_line = strstr(msg, "REPLY_NONCE:");
        if (reply_nonce_line && reply_nonce_line < pubkey_line) {
            char reply_nonce_str[SESSION_NONCE_LEN] = {0};
            sscanf(reply_nonce_line, "REPLY_NONCE:%31s", reply_nonce_str);
            *reply_nonce = strtoull(reply_nonce_str, NULL, 10);
        } else {
            *reply_nonce = 0;
        }
    }
    // PUBKEY: from after 'PUBKEY:' to before 'SIG:'
    const char *pubkey_start = pubkey_line + strlen("PUBKEY:");
    const char *pubkey_end = sig_line;
    size_t pk_len = (size_t)(pubkey_end - pubkey_start);
    if (pk_len >= pubkey_len)
        pk_len = pubkey_len - 1;
    strncpy(pubkey, pubkey_start, pk_len);
    pubkey[pk_len] = '\0';
    // SIG: from after 'SIG:' to end of line
    const char *sig_start = sig_line + strlen("SIG:");
    const char *sig_end = strchr(sig_start, '\n');
    size_t s_len = sig_end ? (size_t)(sig_end - sig_start) : strlen(sig_start);
    if (s_len >= sig_len)
        s_len = sig_len - 1;
    strncpy(sig, sig_start, s_len);
    sig[s_len] = '\0';
    return 0;
}

size_t protocol_prepare_plain_msg(char *buffer, size_t buf_len, const char *message) {
    return snprintf(buffer, buf_len, "TYPE:%s\nMESSAGE:%s\nEND\n", protocol_type_to_str(PROTOCOL_MSG), message);
}

size_t protocol_parse_plain_msg(const char *msg, char *body, size_t body_len) {
    const char *body_line = strstr(msg, "MESSAGE:");
    if (!body_line) {
        body[0] = '\0';
        return 0;
    }
    const char *body_start = body_line + 8;
    const char *body_end = strchr(body_start, '\n');
    size_t len = body_end ? (size_t)(body_end - body_start) : strlen(body_start);
    if (len >= body_len)
        len = body_len - 1;
    strncpy(body, body_start, len);
    body[len] = '\0';
    return len;
}

ProtocolType protocol_parse_message(const char *msg, char *body, size_t body_len) {
    const char *type_line = strstr(msg, "TYPE:");
    if (!type_line)
        return PROTOCOL_ERROR;
    const char *type_start = type_line + 5;
    const char *type_end = strchr(type_start, '\n');
    if (!type_end)
        return PROTOCOL_ERROR;
    size_t type_len = type_end - type_start;
    ProtocolType type = protocol_str_to_type(type_start, type_len);
    if (type == PROTOCOL_ERROR)
        return PROTOCOL_ERROR;
    const char *body_start = type_end + 1;
    const char *end_line = strstr(body_start, "\nEND");
    if (!end_line)
        return PROTOCOL_ERROR;
    size_t body_sz = (size_t)(end_line - body_start);
    if (body_sz >= body_len)
        body_sz = body_len - 1;
    strncpy(body, body_start, body_sz);
    body[body_sz] = '\0';
    return type;
}
