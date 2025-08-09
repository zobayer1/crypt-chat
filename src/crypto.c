//
// Created by zobayer on 7/17/25.
//
#include "crypto.h"

#include <sys/time.h>

void uuid_random(uuid_t *uuid) { uuid_generate_random(*uuid); }

void uuid_str(const uuid_t uuid, char *out) { uuid_unparse(uuid, out); }

uint64_t generate_nonce() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int nonce_within_grace(uint64_t nonce1, uint64_t nonce2) {
    return NONCE_GRACE_PERIOD_MS >= (nonce1 > nonce2 ? nonce1 - nonce2 : nonce2 - nonce1);
}
