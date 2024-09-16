#include "key.h"

#include <assert.h>
#include <pthread.h>

#include "error.h"
#include "logger.h"
#include "openssl/aes.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rand.h"

struct super_key_operation {
    int (*create)(struct key_context *, const enum key_type);
    int (*import_pubkey)(struct key_context *, const enum key_type, const uint8_t *, const int);
    int (*import_prikey)(struct key_context *, const enum key_type, const uint8_t *, const int);
};

const struct super_key_operation *super_key_ops[KEY_TYPE_NUM - 1] = {0};

struct key_operation {
    int (*encrypt)(const struct key_context *ctx, const uint8_t *, const int, uint8_t *, int *);
    int (*decrypt)(const struct key_context *ctx, const uint8_t *, const int, uint8_t *, int *);

    int (*sign)(const struct key_context *ctx, const uint8_t *, const int, uint8_t *, int *);
    int (*verify)(const struct key_context *ctx, const uint8_t *, const int, const uint8_t *,
                  const int);
};

struct key_context {
    enum key_type type;
    void *context;

    struct key_operation *ops;

    void (*free_context)(void *);
};

#define CREATE_KEY_CONTEXT(ops, args...)                                             \
    ({                                                                               \
        int ret = E_PARAM;                                                           \
        if (likely(type > UNKNOWN_KEY_TYPE && type < KEY_TYPE_NUM)) {                \
            const struct super_key_operation *sko = super_key_ops[type];             \
            if (likely(sko && sko->ops)) {                                           \
                if (unlikely(*ctx)) free_key_context(*ctx);                          \
                *ctx = (struct key_context *)malloc(sizeof(struct key_context) + 1); \
                if (likely(*ctx)) {                                                  \
                    ret = sko->ops(*ctx, ##args);                                    \
                    if (unlikely(ret < 0)) free(*ctx);                               \
                } else {                                                             \
                    ret = E_MEM;                                                     \
                }                                                                    \
            } else {                                                                 \
                ret = E_NOTIMPL;                                                     \
            }                                                                        \
        }                                                                            \
        ret;                                                                         \
    })

int create_key_context(struct key_context **ctx, const enum key_type type) {
    return CREATE_KEY_CONTEXT(create, type);
}
int pubkey_to_key_context(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                          const int len) {
    return CREATE_KEY_CONTEXT(import_pubkey, type, k, len);
}
int prikey_to_key_context(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                          const int len) {
    return CREATE_KEY_CONTEXT(import_pubkey, type, k, len);
}

#undef CREATE_KEY_CONTEXT

void free_key_context(struct key_context *ctx) {
    if (!ctx) return;

    assert(ctx->free_context);
    ctx->free_context(ctx->context);
    ctx->context = NULL;

    free(ctx);
    ctx = NULL;
}

#define KEY_CONTEXT_OPS(func, args...)                \
    ({                                                \
        int ret = E_PARAM;                            \
        if (likely(ctx && ctx->context)) {            \
            if (likely(ctx->ops && ctx->ops->func)) { \
                ret = ctx->ops->func(ctx, ##args);    \
            } else {                                  \
                ret = E_NOTIMPL;                      \
            }                                         \
        }                                             \
        ret;                                          \
    })

int encrypt_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                     int *olen) {
    return KEY_CONTEXT_OPS(encrypt, in, ilen, out, olen);
}
int decrypt_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                     int *olen) {
    return KEY_CONTEXT_OPS(decrypt, in, ilen, out, olen);
}

int sign_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                  int *slen) {
    return KEY_CONTEXT_OPS(sign, in, ilen, sig, slen);
}
int verify_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, const uint8_t *sig,
                    const int slen) {
    return KEY_CONTEXT_OPS(verify, in, ilen, sig, slen);
}

#undef KEY_CONTEXT_OPS

/******************************RAND********************************/
#ifdef __GNUC__
#define RAND_SEED_FILE "/dev/urandom"
#endif

#define READ_RAND_SEEDS_NUM 1024
pthread_mutex_t rand_lock;
int get_rand(uint8_t *buf, int len) {
    int ret = E_RAND;
    pthread_mutex_lock(&rand_lock);
    RAND_cleanup();
    if (RAND_load_file(RAND_SEED_FILE, READ_RAND_SEEDS_NUM) != READ_RAND_SEEDS_NUM) goto err;
    if (RAND_status() != 1) goto err;
    if (RAND_bytes(buf, len) != 1) goto err;
    ret = E_OK;
err:
    pthread_mutex_unlock(&rand_lock);
    return ret;
}
#undef READ_RAND_SEEDS_NUM

int init_rand() {
    pthread_mutex_init(&rand_lock, NULL);

    logger_trace("init rand ok");
    return E_OK;
}

struct symmetric_key {
    uint8_t key[SYMMETRIC_KEY_LEN + BLOCK_SIZE + 1];
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
};

/******************************AES********************************/
int key_aes_crypto(const struct key_context *ctx, const int flag, const uint8_t *in, const int ilen,
                   uint8_t *out, int *olen) {
    int ret = 0, tmp = 0, aes_flen = 0;

    assert(ctx && ctx->context);
    struct symmetric_key *sk = (struct symmetric_key *)(ctx->context);
    const uint8_t *key = sk->key;
    const uint8_t *iv = key + SYMMETRIC_KEY_LEN;

    assert(sk->ctx && sk->cipher && in && out);
    tmp = EVP_CipherInit_ex(sk->ctx, sk->cipher, NULL, key, iv, flag);
    if (unlikely(tmp != 1 ? (ret = E_AES) : 0)) goto err;
    tmp = EVP_CipherUpdate(sk->ctx, out, olen, in, ilen);
    if (unlikely(tmp != 1 ? (ret = E_AES) : 0)) goto err;
    tmp = EVP_CipherFinal(sk->ctx, out + *olen, &aes_flen);
    if (unlikely(tmp != 1 ? (ret = E_AES) : 0)) goto err;

    *olen += aes_flen;

err:
    EVP_CIPHER_CTX_reset(sk->ctx);
    return ret;
}
int key_aes_encrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    int *olen) {
    return key_aes_crypto(ctx, AES_ENCRYPT, in, ilen, out, olen);
}
int key_aes_decrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    int *olen) {
    return key_aes_crypto(ctx, AES_DECRYPT, in, ilen, out, olen);
}

struct key_operation key_aes_operation = {&key_aes_encrypt, &key_aes_decrypt, NULL, NULL};

void free_aes_key(void *k) {
    if (likely(k)) {
        struct symmetric_key *sk = (struct symmetric_key *)k;
        if (sk->ctx) {
            EVP_CIPHER_CTX_free(sk->ctx);
            sk->ctx = NULL;
        }

        free(sk);
    }
}
int create_aes_key(struct key_context *ctx, const enum key_type type) {
    struct symmetric_key *sk = NULL;
    int ret = E_OK;

    sk = (struct symmetric_key *)malloc(sizeof(struct symmetric_key));
    if (unlikely(!sk)) return E_MEM;
    sk->ctx = EVP_CIPHER_CTX_new();
    if (unlikely(!sk->ctx)) return E_OPENSSLMEM;

    memset(sk->key, 0, sizeof(sk->key));
    if ((ret = get_rand(sk->key, SYMMETRIC_KEY_LEN)) < 0) {
        EVP_CIPHER_CTX_free(sk->ctx);
        free_aes_key((void *)sk);
        return ret;
    }

    switch (type) {
        case KEY_AES_128_CBC: {
            sk->cipher = EVP_aes_128_cbc();
        } break;
        case KEY_AES_192_CBC: {
            sk->cipher = EVP_aes_192_cbc();
        } break;
        case KEY_AES_256_CBC: {
            sk->cipher = EVP_aes_256_cbc();
        } break;
        default:
            assert(0);
    }

    assert(ctx);
    ctx->type = type;
    ctx->context = (void *)sk;
    ctx->ops = &key_aes_operation;
    ctx->free_context = &free_aes_key;

    logger_trace("create aes key[%s] ok", get_key_type(type));
    return E_OK;
}

const struct super_key_operation super_aes_key_ops = {&create_aes_key, NULL, NULL};

int init_aes_key() {
    super_key_ops[KEY_AES_128_CBC] = &super_aes_key_ops;
    super_key_ops[KEY_AES_192_CBC] = &super_aes_key_ops;
    super_key_ops[KEY_AES_256_CBC] = &super_aes_key_ops;

    logger_trace("init aes key ok");
    return E_OK;
}

/******************************initialize********************************/
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()

void handle_error(const char *file, int lineno, const char *msg) {
    fprintf(stderr, "** %s:%d %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    /* exit(-1); */
}

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL;

static void locking_function(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(mutex_buf[n]);
    else
        MUTEX_UNLOCK(mutex_buf[n]);
}

static size_t id_function(void) { return ((size_t)THREAD_ID); }

int OpenSSL_thread_setup(void) {
    int i;

    mutex_buf = malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
    if (!mutex_buf) return E_MEM;
    for (i = 0; i < CRYPTO_num_locks(); i++) MUTEX_SETUP(mutex_buf[i]);
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return E_OK;
}

int openssl_thread_cleanup(void) {
    int i;

    if (!mutex_buf) return E_PARAM;
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) MUTEX_CLEANUP(mutex_buf[i]);
    free(mutex_buf);
    mutex_buf = NULL;
    return E_OK;
}

int init_OpenSSL() {
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ERR_load_crypto_strings();

    ERR_load_crypto_strings();
    ERR_clear_error();

    return OpenSSL_thread_setup();
}

int init_keys() {
    int ret = E_OK;
    if ((ret = init_OpenSSL()) < 0) return ret;
    if ((ret = init_rand()) < 0) return ret;
    if ((ret = init_aes_key()) < 0) return ret;

    logger_trace("init keys ok");
    return ret;
}