#include "key.h"

#include <assert.h>
#include <pthread.h>

#include "error.h"
#include "logger.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/core_names.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"

struct super_key_operation {
    int (*create)(struct key_context *, const enum key_type);
    int (*import_pubkey)(struct key_context *, const enum key_type, const uint8_t *, const int);
    int (*import_prikey)(struct key_context *, const enum key_type, const uint8_t *, const int);
};

const struct super_key_operation *super_key_ops[KEY_TYPE_NUM] = {0};

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

#define CREATE_KEY_CONTEXT(ops, args...)                                                     \
    ({                                                                                       \
        int ret = E_PARAM;                                                                   \
        if (likely(type > UNKNOWN_KEY_TYPE && type < KEY_TYPE_NUM)) {                        \
            const struct super_key_operation *sko = super_key_ops[type];                     \
            if (likely(sko && sko->ops)) {                                                   \
                if (unlikely(*ctx)) free_key_context(*ctx);                                  \
                *ctx = (struct key_context *)malloc(sizeof(struct key_context) + 1);         \
                if (likely(*ctx)) {                                                          \
                    ret = sko->ops(*ctx, ##args);                                            \
                    if (unlikely(ret < 0)) free(*ctx);                                       \
                } else {                                                                     \
                    ret = E_MEM;                                                             \
                }                                                                            \
            } else {                                                                         \
                ret = E_NOTIMPL;                                                             \
            }                                                                                \
        }                                                                                    \
        if (ret < 0)                                                                         \
            logger_error("create key[%s] failed: %s", get_key_type(type), get_err_msg(ret)); \
        ret;                                                                                 \
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
    if (unlikely(!sk->ctx)) return E_MEM;

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

/***********************EVP for asymmetic key****************************/
struct evp_key {
    void *key;

    int (*create)(EVP_PKEY_CTX **, void *);
    void (*get_optional_params)(OSSL_PARAM *, void *);
};

#define EVP_PKEY_OPERATOR(func, ctx, in, ilen, out, olen)                            \
    EVP_PKEY_CTX *pkey_ctx = NULL;                                                   \
    OSSL_PARAM params[5];                                                            \
    int ret = E_OK, buf_len = 0;                                                     \
                                                                                     \
    if (unlikely(!ctx || !ctx->context || !in || !out)) return E_PARAM;              \
    struct evp_key *ek = (struct evp_key *)(ctx->context);                           \
    assert(ek->key && ek->create && ek->get_optional_params);                        \
                                                                                     \
    /* create evp pkey */                                                            \
    if ((ret = ek->create(&pkey_ctx, ek->key)) < 0) goto out;                        \
                                                                                     \
    /* If no optional parameters are required then NULL can be passed */             \
    ek->get_optional_params(params, ek->key);                                        \
    if (EVP_PKEY_##func##_init_ex(pkey_ctx, params) < 1) goto err;                   \
                                                                                     \
    /* calculate the size required to hold the #func data */                         \
    if (EVP_PKEY_##func(pkey_ctx, NULL, (size_t *)&buf_len, in, ilen) < 1) goto err; \
    if ((*olen < buf_len) ? (ret = E_BUFLEN) : 0) goto out;                          \
    if (EVP_PKEY_##func(pkey_ctx, out, (size_t *)olen, in, ilen) == 1) goto out;     \
                                                                                     \
    /* fprintf(stdout, #func " result:\n"); */                                       \
    /* BIO_dump_indent_fp(stdout, out, *olen, 2); */                                 \
    /* fprintf(stdout, "\n"); */                                                     \
                                                                                     \
    err:                                                                             \
    ret = E_EVP;                                                                     \
    out:                                                                             \
    EVP_PKEY_CTX_free(pkey_ctx);                                                     \
    return ret;

int key_evp_encrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    int *olen) {
    EVP_PKEY_OPERATOR(encrypt, ctx, in, ilen, out, olen);
}
int key_evp_decrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    int *olen) {
    EVP_PKEY_OPERATOR(decrypt, ctx, in, ilen, out, olen);
}

int key_evp_sign(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                 int *slen) {
    EVP_PKEY_OPERATOR(sign, ctx, in, ilen, sig, slen);
}
int key_evp_verify(const struct key_context *ctx, const uint8_t *in, const int ilen,
                   const uint8_t *sig, const int slen) {
    EVP_PKEY_CTX *pkey_ctx = NULL;
    OSSL_PARAM params[5];
    int ret = E_OK, buf_len = 0;

    if (unlikely(!ctx || !ctx->context || !in || !sig)) return E_PARAM;
    struct evp_key *ek = (struct evp_key *)(ctx->context);
    assert(ek->key && ek->create && ek->get_optional_params);

    /* create evp pkey */
    if ((ret = ek->create(&pkey_ctx, ek->key)) < 0) goto out;

    /* If no optional parameters are required then NULL can be passed */
    ek->get_optional_params(params, ek->key);
    if (EVP_PKEY_verify_init_ex(pkey_ctx, params) < 1) goto err;

    if (EVP_PKEY_verify(pkey_ctx, sig, (size_t)slen, in, ilen) == 1) goto out;

    /* fprintf(stdout, #func " result:\n"); */
    /* BIO_dump_indent_fp(stdout, out, *olen, 2); */
    /* fprintf(stdout, "\n"); */

err:
    ret = E_EVP;
out:
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}

struct key_operation key_evp_operation = {&key_evp_encrypt, &key_evp_decrypt, &key_evp_sign,
                                          &key_evp_verify};

/*********************************RSA************************************/
struct rsa_key {
    EVP_PKEY *pkey;
    int padding;
};

int create_rsa_evp_ctx(EVP_PKEY_CTX **ctx, void *k) {
    assert(k);
    struct rsa_key *rk = (struct rsa_key *)k;

    assert(rk->pkey);
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    (*ctx) = EVP_PKEY_CTX_new_from_pkey(libctx, rk->pkey, propq);
    if (unlikely(!(*ctx))) return E_RSA;

    return E_OK;
}

void get_rsa_optional_params(OSSL_PARAM *p, void *k) {
    assert(p && k);
    struct rsa_key *rk = (struct rsa_key *)k;

    /* 1. set padding */
    switch (rk->padding) {
            /* "pkcs1" is used by default if the padding mode is not set */
        case RSA_PKCS1_PADDING:
            break;
        case RSA_PKCS1_OAEP_PADDING: {
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                    OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
        } break;
        case RSA_PKCS1_PSS_PADDING:
            break;
        default:
            break;
    }

    /* 2. set hash method */
    // /* "SHA1" is used if this is not set */
    // *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
    //                                         "SHA256", 0);

    *p = OSSL_PARAM_construct_end();
}

void free_rsa_key(void *k) {
    if (unlikely(k)) return;

    struct evp_key *ek = (struct evp_key *)k;
    assert(ek->key);

    struct rsa_key *rk = (struct rsa_key *)(ek->key);
    if (rk->pkey) {
        EVP_PKEY_free(rk->pkey);
        rk->pkey = NULL;
    }
    free(rk);

    ek->key = NULL;
    free(ek);
}

int create_rsa_key(struct key_context *ctx, const enum key_type type) {
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    uint8_t primes = 2;
    int ret = E_OK;

    /* create rsa context */
    struct evp_key *ek = (struct evp_key *)malloc(sizeof(struct evp_key) + 1);
    struct rsa_key *rk = (struct rsa_key *)malloc(sizeof(struct rsa_key) + 1);
    if ((!ek || !rk) ? (ret = E_MEM) : 0) goto err;

    /* Create context using RSA algorithm. "RSA-PSS" could also be used here. */
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    if (!(genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", propq))) goto rsar;

    /* Initialize context for key generation purposes. */
    if (EVP_PKEY_keygen_init(genctx) < 1) goto rsar;

    /*
     * Here we set the number of bits to use in the RSA key.
     * See comment at top of file for information on appropriate values.
     */
    int bits = 4096;
    switch (type) {
        case KEY_RSA_1024: {
            bits = 1024;
        } break;
        case KEY_RSA_2048: {
            bits = 2048;
        } break;
        case KEY_RSA_4096:
            break;
        default:
            assert(0);
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) < 1) goto rsar;

    /*
     * It is possible to create an RSA key using more than two primes.
     * Do not do this unless you know why you need this.
     * You ordinarily do not need to specify this, as the default is two.
     *
     * Both of these parameters can also be set via EVP_PKEY_CTX_set_params, but
     * these functions provide a more concise way to do so.
     */
    if (EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) < 1) goto rsar;

    /*
     * Generating an RSA key with a number of bits large enough to be secure for
     * modern applications can take a fairly substantial amount of time (e.g.
     * one second). If you require fast key generation, consider using an EC key
     * instead.
     *
     * If you require progress information during the key generation process,
     * you can set a progress callback using EVP_PKEY_set_cb; see the example in
     * EVP_PKEY_generate(3).
     */
    if (EVP_PKEY_generate(genctx, &pkey) < 1) goto rsar;

    /* free evp pkey context */
    EVP_PKEY_CTX_free(genctx);

    assert(ctx);
    rk->pkey = pkey;
    rk->padding = RSA_PKCS1_PADDING;  // use pkcs1 padding in default

    ek->key = (void *)rk;
    ek->create = &create_rsa_evp_ctx;
    ek->get_optional_params = &get_rsa_optional_params;

    ctx->type = type;
    ctx->context = (void *)ek;
    ctx->ops = &key_evp_operation;
    ctx->free_context = &free_rsa_key;
    return ret;

rsar:
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(pkey);
    ret = E_GENRSA;
err:
    free(ek);
    free(rk);
    return ret;
}

int set_rsa_padding_to_key_context(struct key_context *ctx, const int padding) {
    if (unlikely(!ctx || !ctx->context)) return E_PARAM;
    if (unlikely(ctx->type <= KEY_RSA_1024 || ctx->type >= KEY_RSA_2048)) return E_PARAM;

    struct evp_key *ek = (struct evp_key *)(ctx->context);
    assert(ek->key);
    struct rsa_key *rk = (struct rsa_key *)(ek->key);
    rk->padding = padding;
    return E_OK;
}

const struct super_key_operation super_rsa_key_ops = {&create_rsa_key, NULL, NULL};
int init_rsa_key() {
    super_key_ops[KEY_RSA_1024] = &super_rsa_key_ops;
    super_key_ops[KEY_RSA_2048] = &super_rsa_key_ops;
    super_key_ops[KEY_RSA_4096] = &super_rsa_key_ops;

    logger_trace("init rsa key ok");
    return E_OK;
}

/********************************ECDSA***********************************/
struct ec_key {
    EVP_PKEY *pkey;
};

int create_ec_evp_ctx(EVP_PKEY_CTX **ctx, void *k) {
    assert(k);
    struct ec_key *eck = (struct ec_key *)k;

    assert(eck->pkey);
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    (*ctx) = EVP_PKEY_CTX_new_from_pkey(libctx, eck->pkey, propq);
    if (unlikely(!(*ctx))) return E_EC;

    return E_OK;
}

void get_ec_optional_params(OSSL_PARAM *p, void *k) {
    assert(p);

    *p = OSSL_PARAM_construct_end();
}

int key_ec_sign(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                int *slen) {
    return key_evp_sign(ctx, in, ilen, sig, slen);
}
int key_ec_verify(const struct key_context *ctx, const uint8_t *in, const int ilen,
                  const uint8_t *sig, const int slen) {
    return key_evp_verify(ctx, in, ilen, sig, slen);
}

struct key_operation key_ec_operation = {NULL, NULL, &key_ec_sign, &key_ec_verify};

void free_ec_key(void *k) {
    if (unlikely(k)) return;

    struct evp_key *ek = (struct evp_key *)k;
    assert(ek->key);

    struct ec_key *eck = (struct ec_key *)(ek->key);
    if (eck->pkey) {
        EVP_PKEY_free(eck->pkey);
        eck->pkey = NULL;
    }
    free(eck);

    ek->key = NULL;
    free(ek);
}

const char *get_curve_name_by_key_type(const enum key_type type) {
    switch (type) {
        case KEY_EC_P256:
            return "P-256";
        default:
            return "";
    }
}

int create_ec_key(struct key_context *ctx, const enum key_type type) {
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[5];
    int use_cofactordh = 1;
    int ret = E_OK;

    const char *curvename = get_curve_name_by_key_type(type);
    if (!curvename) return E_PARAM;

    /* create ec key context */
    struct evp_key *ek = (struct evp_key *)malloc(sizeof(struct evp_key) + 1);
    struct ec_key *eck = (struct ec_key *)malloc(sizeof(struct ec_key) + 1);
    if ((!ek || !eck) ? (ret = E_MEM) : 0) goto err;

    /* Create context using EC algorithm. */
    OSSL_LIB_CTX *libctx = NULL;
    const char *propq = NULL;
    if (!(genctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq))) goto ecr;

    /* Initialize context for key generation purposes. */
    if (EVP_PKEY_keygen_init(genctx) < 1) goto ecr;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)curvename, 0);
    /*
     * This is an optional parameter.
     * For many curves where the cofactor is 1, setting this has no effect.
     */
    params[1] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, &use_cofactordh);
    params[2] = OSSL_PARAM_construct_end();

    /* set params */
    if (EVP_PKEY_CTX_set_params(genctx, params) < 1) goto ecr;

    /* generate EC key */
    if (EVP_PKEY_generate(genctx, &pkey) < 1) goto ecr;

    /* free evp pkey context */
    EVP_PKEY_CTX_free(genctx);

    assert(ctx);
    eck->pkey = pkey;

    ek->key = (void *)eck;
    ek->create = &create_ec_evp_ctx;
    ek->get_optional_params = &get_ec_optional_params;

    ctx->type = type;
    ctx->context = (void *)ek;
    ctx->ops = &key_ec_operation;
    ctx->free_context = &free_ec_key;
    return ret;

ecr:
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(pkey);
    ret = E_GENEC;
err:
    free(ek);
    free(eck);
    return ret;
}

const struct super_key_operation super_ec_key_ops = {&create_ec_key, NULL, NULL};
int init_ec_key() {
    super_key_ops[KEY_EC_P256] = &super_ec_key_ops;

    logger_trace("init ec key ok");
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
    if ((ret = init_rsa_key()) < 0) return ret;
    if ((ret = init_ec_key()) < 0) return ret;

    logger_trace("init keys ok");
    return ret;
}