//
// Created by zobayer on 7/17/25.
//
#include "crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/time.h>

static int handle_openssl_error() {
    ERR_print_errors_fp(stdout);
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

int base64_encode(const unsigned char *in, size_t in_len, char *out) {
    int enc_len = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    if (enc_len < 0)
        return -1;
    out[enc_len] = '\0';
    return enc_len;
}

int base64_decode(const char *in, size_t in_len, unsigned char *out) {
    int dec_len = EVP_DecodeBlock(out, (const unsigned char *)in, (int)in_len);
    if (dec_len < 0)
        return -1;
    while (in_len > 0 && in[in_len - 1] == '=') {
        dec_len--;
        in_len--;
    }
    return dec_len;
}

int generate_aes256_key(unsigned char *key) {
    if (RAND_bytes(key, 32) != 1) {
        return handle_openssl_error();
    }
    return 0;
}

int rsa_encrypt_key(const char *pubkey_pem, const unsigned char *key, size_t key_len, unsigned char *enc,
                    size_t *enc_len) {
    BIO *bio = BIO_new_mem_buf(pubkey_pem, -1);
    if (!bio)
        return handle_openssl_error();
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        return handle_openssl_error();
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    size_t out_len = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, key, key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    if (enc == NULL || *enc_len < out_len) {
        *enc_len = out_len;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return -1;
    }
    if (EVP_PKEY_encrypt(ctx, enc, &out_len, key, key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    *enc_len = out_len;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return 0;
}

int rsa_decrypt_key(const char *privkey_pem, const unsigned char *enc, size_t enc_len, unsigned char *key,
                    size_t *key_len) {
    BIO *bio = BIO_new_mem_buf(privkey_pem, -1);
    if (!bio) {
        return handle_openssl_error();
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        return handle_openssl_error();
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    size_t out_len = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, enc, enc_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    if (key == NULL || *key_len < out_len) {
        *key_len = out_len;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return -1;
    }
    if (EVP_PKEY_decrypt(ctx, key, &out_len, enc, enc_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return handle_openssl_error();
    }
    *key_len = out_len;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return 0;
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *out) {
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = hex_digits[(bytes[i] >> 4) & 0xF];
        out[2 * i + 1] = hex_digits[bytes[i] & 0xF];
    }
    out[2 * len] = '\0';
}

int aes256_gcm_encrypt(const char *buffer, const unsigned char *aeskey, unsigned char *out, size_t out_len,
                       unsigned char *iv, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ciphertext_len = 0;
    if (!ctx)
        return -1;
    if (RAND_bytes(iv, 12) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aeskey, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    size_t plaintext_len = strlen(buffer);
    if (out_len < plaintext_len) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptUpdate(ctx, out, &len, (const unsigned char *)buffer, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes256_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *aeskey,
                       const unsigned char *iv, const unsigned char *tag, char *out, size_t out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    size_t plaintext_len = 0;
    if (!ctx)
        return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aeskey, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptUpdate(ctx, (unsigned char *)out, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)out + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        plaintext_len += len;
        if (plaintext_len >= out_len)
            plaintext_len = out_len - 1;
        out[plaintext_len] = '\0';
        return (int)plaintext_len;
    }
    return -1;
}
