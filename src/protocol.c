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
    case PROTOCOL_CIPHER:
        return "CIPHER";
    case PROTOCOL_PUBKEY_OFFER:
        return "PUBKEY_OFFER";
    case PROTOCOL_PUBKEY_RESP:
        return "PUBKEY_RESP";
    case PROTOCOL_SESSKEY_OFFER:
        return "SESSKEY_OFFER";
    case PROTOCOL_SESSKEY_RESP:
        return "SESSKEY_RESP";
    case PROTOCOL_ERROR:
    default:
        return "ERROR";
    }
}

static ProtocolType protocol_str_to_type(const char *type_str, size_t type_len) {
    if (type_len == 3 && strncmp(type_str, "BYE", type_len) == 0)
        return PROTOCOL_BYE;
    if (type_len == 6 && strncmp(type_str, "REJECT", type_len) == 0)
        return PROTOCOL_REJECT;
    if (type_len == 5 && strncmp(type_str, "ERROR", type_len) == 0)
        return PROTOCOL_ERROR;
    if (type_len == 8 && strncmp(type_str, "CONN_ACK", type_len) == 0)
        return PROTOCOL_CONN_ACK;
    if (type_len == 4 && strncmp(type_str, "CONN", type_len) == 0)
        return PROTOCOL_CONN;
    if (type_len == 3 && strncmp(type_str, "MSG", type_len) == 0)
        return PROTOCOL_MSG;
    if (type_len == 6 && strncmp(type_str, "CIPHER", type_len) == 0)
        return PROTOCOL_CIPHER;
    if (type_len == 12 && strncmp(type_str, "PUBKEY_OFFER", type_len) == 0)
        return PROTOCOL_PUBKEY_OFFER;
    if (type_len == 11 && strncmp(type_str, "PUBKEY_RESP", type_len) == 0)
        return PROTOCOL_PUBKEY_RESP;
    if (type_len == 13 && strncmp(type_str, "SESSKEY_OFFER", type_len) == 0)
        return PROTOCOL_SESSKEY_OFFER;
    if (type_len == 12 && strncmp(type_str, "SESSKEY_RESP", type_len) == 0)
        return PROTOCOL_SESSKEY_RESP;
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

int protocol_parse_conn_msg(const char *msg, UserSession *session, uint64_t *nonce, uint64_t *reply_nonce) {
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
    return 0;
}

size_t protocol_prepare_dc_msg(char *buffer, size_t buf_len, ProtocolType type, const char *reason) {
    const char *type_str = protocol_type_to_str(type);
    if (reason && strlen(reason) > 0) {
        return snprintf(buffer, buf_len, "TYPE:%s\nREASON:%s\nEND\n", type_str, reason);
    }
    return snprintf(buffer, buf_len, "TYPE:%s\nEND\n", type_str);
}

int protocol_parse_dc_msg(const char *msg, char *reason, size_t reason_len) {
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
    return (int)len;
}

size_t protocol_prepare_pkey_offer_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                       const char *signature) {
    char uuid_str[SESSION_ID_LEN];
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len, "TYPE:%s\nID:%s\nNONCE:%" PRIu64 "\nPUBKEY:%s\nSIG:%s\nEND\n",
                    protocol_type_to_str(PROTOCOL_PUBKEY_OFFER), uuid_str, nonce,
                    session->pubkey ? session->pubkey : "", signature ? signature : "");
}

size_t protocol_prepare_pkey_resp_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                      uint64_t reply_nonce, const char *signature) {
    char uuid_str[SESSION_ID_LEN];
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len,
                    "TYPE:%s\nID:%s\nNONCE:%" PRIu64 "\nREPLY_NONCE:%" PRIu64 "\nPUBKEY:%s\nSIG:%s\nEND\n",
                    protocol_type_to_str(PROTOCOL_PUBKEY_RESP), uuid_str, nonce, reply_nonce,
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

int protocol_parse_plain_msg(const char *msg, char *body, size_t body_len) {
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
    return (int)len;
}

size_t protocol_prepare_sesskey_offer_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                          const char *aeskey_b64, const char *sig_b64) {
    char uuid_str[SESSION_ID_LEN] = {0};
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len, "TYPE:%s\nID:%s\nNONCE:%" PRIu64 "\nAESKEY:%s\nSIG:%s\nEND\n",
                    protocol_type_to_str(PROTOCOL_SESSKEY_OFFER), uuid_str, nonce, aeskey_b64, sig_b64);
}

size_t protocol_prepare_sesskey_resp_msg(char *buffer, size_t buf_len, const UserSession *session, uint64_t nonce,
                                         uint64_t reply_nonce, const char *sig_b64) {
    char uuid_str[SESSION_ID_LEN] = {0};
    uuid_unparse(session->sid, uuid_str);
    return snprintf(buffer, buf_len, "TYPE:%s\nID:%s\nNONCE:%" PRIu64 "\nREPLY_NONCE:%" PRIu64 "\nSIG:%s\nEND\n",
                    protocol_type_to_str(PROTOCOL_SESSKEY_RESP), uuid_str, nonce, reply_nonce, sig_b64);
}

int protocol_parse_sesskey_msg(const char *msg, uuid_t *id, uint64_t *nonce, uint64_t *reply_nonce, char *aeskey_b64,
                               size_t aeskey_b64_len, char *sig_b64, size_t sig_b64_len) {
    char uuid_str[SESSION_ID_LEN] = {0};
    char nonce_str[SESSION_NONCE_LEN] = {0};
    char reply_nonce_str[SESSION_NONCE_LEN] = {0};
    // ID
    const char *id_line = strstr(msg, "ID:");
    if (!id_line)
        return -1;
    sscanf(id_line, "ID:%36s", uuid_str);
    uuid_parse(uuid_str, *id);
    // NONCE
    const char *nonce_line = strstr(msg, "NONCE:");
    if (!nonce_line)
        return -1;
    sscanf(nonce_line, "NONCE:%31s", nonce_str);
    if (nonce)
        *nonce = strtoull(nonce_str, NULL, 10);
    // Optional REPLY_NONCE (only in RESP)
    if (reply_nonce) {
        const char *reply_nonce_line = strstr(msg, "REPLY_NONCE:");
        if (reply_nonce_line) {
            sscanf(reply_nonce_line, "REPLY_NONCE:%31s", reply_nonce_str);
            *reply_nonce = strtoull(reply_nonce_str, NULL, 10);
        } else {
            *reply_nonce = 0;
        }
    }
    // Optional AESKEY (only in OFFER)
    if (aeskey_b64 && aeskey_b64_len > 0) {
        const char *aeskey_line = strstr(msg, "AESKEY:");
        if (aeskey_line) {
            const char *aeskey_start = aeskey_line + strlen("AESKEY:");
            const char *aeskey_end = strchr(aeskey_start, '\n');
            size_t len = aeskey_end ? (size_t)(aeskey_end - aeskey_start) : strlen(aeskey_start);
            if (len >= aeskey_b64_len)
                len = aeskey_b64_len - 1;
            strncpy(aeskey_b64, aeskey_start, len);
            aeskey_b64[len] = '\0';
        } else {
            aeskey_b64[0] = '\0';
        }
    }
    // SIG (required)
    const char *sig_line = strstr(msg, "SIG:");
    if (!sig_line)
        return -1;
    const char *sig_start = sig_line + strlen("SIG:");
    const char *sig_end = strchr(sig_start, '\n');
    size_t sig_len = sig_end ? (size_t)(sig_end - sig_start) : strlen(sig_start);
    if (sig_len >= sig_b64_len)
        sig_len = sig_b64_len - 1;
    strncpy(sig_b64, sig_start, sig_len);
    sig_b64[sig_len] = '\0';
    return 0;
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
