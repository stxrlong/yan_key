#ifndef __CRYPTO_KEY_H__
#define __CRYPTO_KEY_H__

#include <stdint.h>
#include <string.h>

#include "key_com.h"

struct key_context;

/**
 * @brief initialize the key operators
 */
int init_keys();

/**
 * @brief create a key context object
 */
int create_key_context(struct key_context **ctx, const enum key_type type);
int pubkey_to_key_context(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                          const int len);
int prikey_to_key_context(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                          const int len);
/**
 * @brief this is only used for RSA, we use RSA_PKCS1_PADDING in default
 */
int set_rsa_padding_to_key_context(struct key_context *ctx, const int padding);
/**
 * @brief all key context should be freed by this func, otherwise, you will get memleak
 */
void free_key_context(struct key_context *ctx);

/**
 * @brief operate with the key context
 */
int encrypt_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                     int *olen);
int decrypt_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                     int *olen);

int sign_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                  int *slen);
int verify_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, const uint8_t *sig,
                    const int slen);

#endif