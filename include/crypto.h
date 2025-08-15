//
// Created by zobayer on 7/17/25.
//
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <uuid/uuid.h>

#define NONCE_GRACE_PERIOD_MS (5 * 60 * 1000)
#define RSA2048_PUBKEY_PEM_SIZE 2048
#define RSA2048_PRIVKEY_PEM_SIZE 8192
#define RSA2048_SIG_PEM_SIZE 512

void uuid_random(uuid_t *uuid);

void uuid_to_str(const uuid_t uuid, char *out);

uint64_t generate_nonce();

int nonce_within_grace(uint64_t nonce1, uint64_t nonce2);

int generate_rsa_keypair(char *pubkey_pem, int pubkey_len, char *privkey_pem, int privkey_len);

int rsa_sign_message(const char *privkey_pem, const unsigned char *msg, size_t msg_len, unsigned char **sig,
                     size_t *sig_len);

int rsa_verify_signature(const char *pubkey_pem, const unsigned char *msg, size_t msg_len, const unsigned char *sig,
                         size_t sig_len);

int base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len);

int base64_decode(const char *in, size_t in_len, unsigned char *out, size_t out_len);

#endif // CRYPTO_H
