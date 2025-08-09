//
// Created by zobayer on 7/17/25.
//
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <uuid/uuid.h>

#define NONCE_GRACE_PERIOD_MS (5 * 60 * 1000)

void uuid_random(uuid_t *uuid);

void uuid_str(const uuid_t uuid, char *out);

uint64_t generate_nonce();

int nonce_within_grace(uint64_t nonce1, uint64_t nonce2);

#endif // CRYPTO_H
