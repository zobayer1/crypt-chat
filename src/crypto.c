//
// Created by zobayer on 7/17/25.
//
#include "crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/time.h>

static int handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    return EXIT_FAILURE;
}

void uuid_random(uuid_t *uuid) { uuid_generate_random(*uuid); }

void uuid_to_str(const uuid_t uuid, char *out) { uuid_unparse(uuid, out); }

uint64_t generate_nonce() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int nonce_within_grace(uint64_t nonce1, uint64_t nonce2) {
    return NONCE_GRACE_PERIOD_MS >= (nonce1 > nonce2 ? nonce1 - nonce2 : nonce2 - nonce1);
}

int generate_rsa_keypair(char *pubkey_pem, int pubkey_len, char *privkey_pem, int privkey_len) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return handle_openssl_error();
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return handle_openssl_error();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        return handle_openssl_error();

    printf("Generating RSA 2048-bit key pair...\n");
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        return handle_openssl_error();

    BIO *bio_pub = BIO_new(BIO_s_mem());
    BIO *bio_priv = BIO_new(BIO_s_mem());
    if (!bio_pub || !bio_priv)
        return handle_openssl_error();
    if (PEM_write_bio_PUBKEY(bio_pub, pkey) != 1)
        return handle_openssl_error();
    if (PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL) != 1)
        return handle_openssl_error();

    int pub_len = BIO_pending(bio_pub);
    int priv_len = BIO_pending(bio_priv);
    if (pubkey_len < pub_len + 1 || privkey_len < priv_len + 1) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(bio_pub);
        BIO_free_all(bio_priv);
        return EXIT_FAILURE;
    }

    BIO_read(bio_pub, pubkey_pem, pub_len);
    BIO_read(bio_priv, privkey_pem, priv_len);

    pubkey_pem[pub_len] = '\0';
    privkey_pem[priv_len] = '\0';
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(bio_pub);
    BIO_free_all(bio_priv);

    return 0;
}

int rsa_sign_message(const char *privkey_pem, const unsigned char *msg, size_t msg_len, unsigned char **sig,
                     size_t *sig_len) {
    BIO *bio = BIO_new_mem_buf(privkey_pem, -1);
    if (!bio)
        return handle_openssl_error();

    EVP_PKEY *pkey = NULL;
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey)
        return handle_openssl_error();

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        return handle_openssl_error();
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
        return handle_openssl_error();
    if (EVP_DigestSign(md_ctx, NULL, sig_len, msg, msg_len) <= 0)
        return handle_openssl_error();

    *sig = malloc(*sig_len);
    if (!*sig) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return EXIT_FAILURE;
    }

    if (EVP_DigestSign(md_ctx, *sig, sig_len, msg, msg_len) <= 0)
        return handle_openssl_error();

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return 0;
}

int rsa_verify_signature(const char *pubkey_pem, const unsigned char *msg, size_t msg_len, const unsigned char *sig,
                         size_t sig_len) {
    BIO *bio = BIO_new_mem_buf(pubkey_pem, -1);
    if (!bio)
        return handle_openssl_error();

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey)
        return handle_openssl_error();

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
        return handle_openssl_error();

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
        return handle_openssl_error();

    if (EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len) < 0)
        return handle_openssl_error();

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return 0;
}

int base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len) {
    size_t required = 4 * ((in_len + 2) / 3);
    if (out_len <= required)
        return -1;
    int enc_len = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (enc_len < 0)
        return -1;
    out[enc_len] = '\0';
    return enc_len;
}

int base64_decode(const char *in, size_t in_len, unsigned char *out, size_t out_len) {
    size_t required = (in_len / 4) * 3;
    if (out_len < required)
        return -1;
    int dec_len = EVP_DecodeBlock(out, (const unsigned char *)in, (int)in_len);
    if (dec_len < 0)
        return -1;
    while (in_len > 0 && in[in_len - 1] == '=') {
        dec_len--;
        in_len--;
    }
    return dec_len;
}
