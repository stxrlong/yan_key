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
/**
 * @brief change the key's storage format to key context
 */
int import_pubkey(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                  const int klen);
int import_prikey(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                  const int klen, const struct key_context *passwd);

/**
 * @brief get the key's storage format from key context, now we only support 'PEM'
 *
 * there is a difference between pubkey and prikey, you can choose to export the
 * prikey with encryption, if so, you must specify a symmetric key, if not, set
 * the 'passwd' to NULL
 */
int export_pubkey(struct key_context *ctx, uint8_t *out, const int olen);
int export_prikey(struct key_context *ctx, uint8_t *out, const int olen,
                  const struct key_context *passwd);

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
                     const int olen);
int decrypt_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                     const int olen);

int sign_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                  const int slen);
int verify_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, const uint8_t *sig,
                    const int slen);

/**
 * @brief base64 encrypt/decrypt
 */
int base64_encrypt(const uint8_t *in, const int ilen, uint8_t *out, const int olen);
int base64_decrypt(const uint8_t *in, const int ilen, uint8_t *out, const int olen);

#endif