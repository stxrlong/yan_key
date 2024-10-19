#ifndef __CRYPTO_KEY_COM_H__
#define __CRYPTO_KEY_COM_H__

#ifdef __GNUC__
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) x
#define unlikely(x) x
#endif

/**
 * @brief key type
 */
#define FOR_EACH_KEY_TYPE(T) \
    T(AES_128_CBC)           \
    T(AES_192_CBC)           \
    T(AES_256_CBC)           \
    T(RSA_1024)              \
    T(RSA_2048)              \
    T(RSA_4096)              \
    T(EC_P256)

enum key_type {
    UNKNOWN_KEY_TYPE = 0,

#define T(a) KEY_##a,
    FOR_EACH_KEY_TYPE(T)
#undef T

        KEY_TYPE_NUM,
};

const char* get_key_type(const enum key_type);

#define SYMMETRIC_KEY_LEN 32
#define BLOCK_SIZE 16

#endif