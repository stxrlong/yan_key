#include "key.h"

#include <assert.h>
#include <pthread.h>

#include "error.h"
#include "logger.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"

struct super_key_operation {
    int (*create)(struct key_context *, const enum key_type);
    int (*import_pubkey)(struct key_context *, const enum key_type, const uint8_t *, const int);
    int (*import_prikey)(struct key_context *, const enum key_type, const uint8_t *, const int,
                         const struct key_context *);
};

const struct super_key_operation *super_key_ops[KEY_TYPE_NUM] = {0};

struct key_operation {
    int (*encrypt)(const struct key_context *ctx, const uint8_t *, const int, uint8_t *, const int);
    int (*decrypt)(const struct key_context *ctx, const uint8_t *, const int, uint8_t *, const int);

    int (*sign)(const struct key_context *ctx, const uint8_t *, const int, uint8_t *, const int);
    int (*verify)(const struct key_context *ctx, const uint8_t *, const int, const uint8_t *,
                  const int);

    int (*get_pubkey)(const struct key_context *ctx, uint8_t *, const int);
    int (*get_prikey)(const struct key_context *ctx, uint8_t *, const int,
                      const struct key_context *);
};

struct key_context {
    enum key_type type;
    void *context;

    struct key_operation *ops;

    void (*free_context)(void *);
};

#define CREATE_KEY_CONTEXT(ops, args...)                                                       \
    ({                                                                                         \
        int ret = E_PARAM;                                                                     \
        if (likely(type > UNKNOWN_KEY_TYPE && type < KEY_TYPE_NUM)) {                          \
            const struct super_key_operation *sko = super_key_ops[type];                       \
            if (likely(sko && sko->ops)) {                                                     \
                if (!(*ctx)) {                                                                 \
                    *ctx = (struct key_context *)calloc(1, sizeof(struct key_context) + 1);    \
                }                                                                              \
                if (likely(*ctx)) {                                                            \
                    ret = sko->ops(*ctx, ##args);                                              \
                    if (unlikely(ret < 0)) free(*ctx);                                         \
                } else {                                                                       \
                    ret = E_MEM;                                                               \
                }                                                                              \
            } else {                                                                           \
                ret = E_NOTIMPL;                                                               \
            }                                                                                  \
        }                                                                                      \
        if (ret < 0)                                                                           \
            logger_error("%s key[%s] failed: %s", #ops, get_key_type(type), get_err_msg(ret)); \
        ret;                                                                                   \
    })

int create_key_context(struct key_context **ctx, const enum key_type type) {
    return CREATE_KEY_CONTEXT(create, type);
}
int import_pubkey(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                  const int klen) {
    return CREATE_KEY_CONTEXT(import_pubkey, type, k, klen);
}
int import_prikey(struct key_context **ctx, const enum key_type type, const uint8_t *k,
                  const int klen, const struct key_context *passwd) {
    return CREATE_KEY_CONTEXT(import_prikey, type, k, klen, passwd);
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
                     const int olen) {
    return KEY_CONTEXT_OPS(encrypt, in, ilen, out, olen);
}
int decrypt_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                     const int olen) {
    return KEY_CONTEXT_OPS(decrypt, in, ilen, out, olen);
}

int sign_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                  const int slen) {
    return KEY_CONTEXT_OPS(sign, in, ilen, sig, slen);
}
int verify_with_key(struct key_context *ctx, const uint8_t *in, const int ilen, const uint8_t *sig,
                    const int slen) {
    return KEY_CONTEXT_OPS(verify, in, ilen, sig, slen);
}

int export_pubkey(struct key_context *ctx, uint8_t *out, const int olen) {
    return KEY_CONTEXT_OPS(get_pubkey, out, olen);
}
int export_prikey(struct key_context *ctx, uint8_t *out, const int olen,
                  const struct key_context *passwd) {
    return KEY_CONTEXT_OPS(get_prikey, out, olen, passwd);
}

#undef KEY_CONTEXT_OPS

int base64_encrypt(const uint8_t *in, const int ilen, uint8_t *out, const int olen) {
    if (olen < (ilen * 4 / 3 + 1 + 1)) return E_BUFLEN;

    return EVP_EncodeBlock(out, in, ilen);
}
int base64_decrypt(const uint8_t *in, const int ilen, uint8_t *out, const int olen) {
    int ret = E_OK, i;
    if (olen < (ilen * 3 / 4 + 4)) return E_BUFLEN;

    ret = EVP_DecodeBlock(out, in, ilen);
    if (ret == -1) return E_BASE64;

    for (i = ilen - 1; i > 0; --i) {
        if (*(in + i) != '=') break;
        --ret;
        if (i < ilen - 2) return E_BASE64;
    }

    return ret;
}

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
    uint8_t key[SYMMETRIC_KEY_LEN << 2];
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
};

/******************************AES********************************/
int key_aes_crypto(const struct key_context *ctx, const int flag, const uint8_t *in, const int ilen,
                   uint8_t *out, const int olen) {
    int ret = 0, tmp = 0, aes_flen = 0;

    assert(ctx && ctx->context);
    struct symmetric_key *sk = (struct symmetric_key *)(ctx->context);
    const uint8_t *key = sk->key;
    const uint8_t *iv = key + SYMMETRIC_KEY_LEN;

    assert(sk->ctx && sk->cipher && in && out);
    tmp = EVP_CipherInit_ex(sk->ctx, sk->cipher, NULL, key, iv, flag);
    if (unlikely(tmp != 1 ? (ret = E_AES) : 0)) goto err;
    tmp = EVP_CipherUpdate(sk->ctx, out, &ret, in, ilen);
    if (unlikely(tmp != 1 ? (ret = E_AES) : 0)) goto err;
    tmp = EVP_CipherFinal(sk->ctx, out + ret, &aes_flen);
    if (unlikely(tmp != 1 ? (ret = E_AES) : 0)) goto err;

    ret += aes_flen;

err:
    EVP_CIPHER_CTX_reset(sk->ctx);
    return ret;
}
int key_aes_encrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    const int olen) {
    return key_aes_crypto(ctx, AES_ENCRYPT, in, ilen, out, olen);
}
int key_aes_decrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    const int olen) {
    return key_aes_crypto(ctx, AES_DECRYPT, in, ilen, out, olen);
}

int get_aes_key(const struct key_context *ctx, uint8_t *out, const int olen,
                const struct key_context *passwd) {
    uint8_t *key = NULL, *buf = NULL;
    int klen = SYMMETRIC_KEY_LEN + BLOCK_SIZE, blen = ((SYMMETRIC_KEY_LEN + 1) << 2);
    int ret = E_OK;

    if (unlikely(!ctx || !ctx->context)) return E_PARAM;
    struct symmetric_key *sk = (struct symmetric_key *)(ctx->context);
    key = sk->key;
    assert(key);

    if (passwd) {
        buf = (uint8_t *)malloc(blen);
        if (unlikely(!buf)) return E_MEM;

        if ((ret = key_aes_encrypt(passwd, sk->key, klen, buf, blen)) < 0) goto err;

        key = buf;
        klen = ret;

        *out = 'e';
    } else {
        *out = 'p';
    }

    ret = base64_encrypt(key, klen, ++out, olen);
    if (ret < 0) goto err;

    ret += 1;

err:
    free(buf);
    return ret;
}

struct key_operation key_aes_operation = {&key_aes_encrypt, &key_aes_decrypt, NULL, NULL, NULL,
                                          &get_aes_key};

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
    if ((ret = get_rand(sk->key, SYMMETRIC_KEY_LEN + BLOCK_SIZE)) < 0) {
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

int import_aes_key(struct key_context *ctx, const enum key_type type, const uint8_t *k,
                   const int klen, const struct key_context *passwd) {
    struct symmetric_key *sk = NULL;
    int ret = E_OK, tmp;
    uint8_t buf[SYMMETRIC_KEY_LEN << 2] = {0};

    if (unlikely(!k || klen <= 10)) return E_PARAM;

    assert(ctx);
    if (!ctx->context) {
        sk = (struct symmetric_key *)calloc(1, sizeof(struct symmetric_key) + 1);
        if (unlikely(!sk)) return E_MEM;
    } else {
        sk = (struct symmetric_key *)(ctx->context);
    }

    switch (*k) {
        case 'p': {
            ret = base64_decrypt(++k, klen - 1, sk->key, SYMMETRIC_KEY_LEN << 2);
            if (ret != SYMMETRIC_KEY_LEN + BLOCK_SIZE) {
                ret = E_GENAES;
                goto err;
            }
            ret = E_OK;
        } break;
        case 'e': {
            if (!passwd) return E_ENCKEY;

            ret = base64_decrypt(++k, klen - 1, buf, SYMMETRIC_KEY_LEN << 2);
            if (ret != (SYMMETRIC_KEY_LEN << 1)) {
                ret = E_GENAES;
                goto err;
            }
            if ((ret = key_aes_decrypt(passwd, buf, ret, sk->key, sizeof(sk->key))) < 0) goto err;
            ret = E_OK;
        } break;
        default:
            return E_PARAM;
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

    if (ctx->context) {
        EVP_CIPHER_CTX_free(sk->ctx);
        sk->ctx = NULL;
    }

    sk->ctx = EVP_CIPHER_CTX_new();
    if (unlikely(!sk->ctx)) {
        ret = E_MEM;
        goto err;
    }

    ctx->type = type;
    ctx->context = (void *)sk;
    ctx->ops = &key_aes_operation;
    ctx->free_context = &free_aes_key;
    return ret;

err:
    if (!ctx->context) free(sk);
    return ret;
}

const struct super_key_operation super_aes_key_ops = {&create_aes_key, NULL, &import_aes_key};

int init_aes_key() {
    super_key_ops[KEY_AES_128_CBC] = &super_aes_key_ops;
    super_key_ops[KEY_AES_192_CBC] = &super_aes_key_ops;
    super_key_ops[KEY_AES_256_CBC] = &super_aes_key_ops;

    logger_trace("init aes key ok");
    return E_OK;
}

/***********************EVP for asymmetic key****************************/
struct evp_key {
    EVP_PKEY *pkey;

    // featured info for each key type
    void *param;
    int (*set_optional_params)(EVP_PKEY_CTX *, void *);
    void (*free_param)(void *);
};

#define EVP_PKEY_OPERATOR(func, ctx, in, ilen, out, olen)                              \
    EVP_PKEY_CTX *pkey_ctx = NULL;                                                     \
    int ret = E_OK, buf_len = 0;                                                       \
                                                                                       \
    if (unlikely(!ctx || !ctx->context || !in || !out)) return E_PARAM;                \
    struct evp_key *ek = (struct evp_key *)(ctx->context);                             \
    assert(ek->pkey);                                                                  \
                                                                                       \
    /* create evp pkey ctx */                                                          \
    pkey_ctx = EVP_PKEY_CTX_new(ek->pkey, NULL);                                       \
    if (unlikely(!pkey_ctx)) goto err;                                                 \
                                                                                       \
    if (EVP_PKEY_##func##_init(pkey_ctx) < 1) goto err;                                \
                                                                                       \
    /* If no optional parameters are required then NULL can be passed */               \
    if (ek->param) {                                                                   \
        assert(ek->set_optional_params);                                               \
        if ((ret = ek->set_optional_params(pkey_ctx, ek->param)) < 0) goto err;        \
    }                                                                                  \
    /* calculate the size required to hold the #func data */                           \
    if (EVP_PKEY_##func(pkey_ctx, NULL, (size_t *)&buf_len, in, ilen) < 1) goto err;   \
    if ((olen < buf_len) ? (ret = E_BUFLEN) : 0) goto out;                             \
    if ((ret = EVP_PKEY_##func(pkey_ctx, out, (size_t *)(&buf_len), in, ilen)) == 1) { \
        ret = buf_len;                                                                 \
        goto out;                                                                      \
    }                                                                                  \
                                                                                       \
    /* fprintf(stdout, #func " result:\n"); */                                         \
    /* BIO_dump_indent_fp(stdout, out, ret, 2); */                                     \
    /* fprintf(stdout, "\n"); */                                                       \
                                                                                       \
    err:                                                                               \
    ret = E_EVP;                                                                       \
    out:                                                                               \
    EVP_PKEY_CTX_free(pkey_ctx);                                                       \
    return ret;

int key_evp_encrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    const int olen) {
    EVP_PKEY_OPERATOR(encrypt, ctx, in, ilen, out, olen);
}
int key_evp_decrypt(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *out,
                    const int olen) {
    EVP_PKEY_OPERATOR(decrypt, ctx, in, ilen, out, olen);
}

int key_evp_sign(const struct key_context *ctx, const uint8_t *in, const int ilen, uint8_t *sig,
                 const int slen) {
    EVP_PKEY_OPERATOR(sign, ctx, in, ilen, sig, slen);
}
int key_evp_verify(const struct key_context *ctx, const uint8_t *in, const int ilen,
                   const uint8_t *sig, const int slen) {
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ret = E_OK, buf_len = 0;

    if (unlikely(!ctx || !ctx->context || !in || !sig)) return E_PARAM;
    struct evp_key *ek = (struct evp_key *)(ctx->context);
    assert(ek->pkey);

    /* create evp pkey */
    pkey_ctx = EVP_PKEY_CTX_new(ek->pkey, NULL);
    if (unlikely(!pkey_ctx)) goto err;

    if (EVP_PKEY_verify_init(pkey_ctx) < 1) goto err;

    /* If no optional parameters are required then NULL can be passed */
    if (ek->param) {
        assert(ek->set_optional_params);
        if ((ret = ek->set_optional_params(pkey_ctx, ek->param)) < 0) goto err;
    }

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

int get_evp_pubkey(const struct key_context *ctx, uint8_t *out, const int olen) {
    BIO *bp = NULL;
    int ret = E_OK, klen = 0;
    if (unlikely(!ctx || !ctx->context || !out)) return E_PARAM;

    switch (ctx->type) {
        case KEY_RSA_2048:
            klen = 512;
            break;
        case KEY_EC_P256:
            klen = 256;
            break;
        default:
            assert(0 && "unknow key_type");
    }

    if (olen < klen) return E_BUFLEN;

    bp = BIO_new(BIO_s_mem());
    if (unlikely(!bp)) return E_MEM;

    struct evp_key *ek = (struct evp_key *)(ctx->context);
    assert(ek->pkey);
    if (PEM_write_bio_PUBKEY(bp, ek->pkey) < 1) goto err;
    ret = BIO_read(bp, out, olen);
    if (ret > 10) goto out;

err:
    ret = E_EVP;
out:
    BIO_free(bp);
    return ret;
}

int get_evp_prikey(const struct key_context *ctx, uint8_t *out, const int olen,
                   const struct key_context *passwd) {
    BIO *bp = NULL;
    const EVP_CIPHER *cipher = NULL;
    const uint8_t *pass = NULL;

    int ret = E_OK, klen = 0;
    if (unlikely(!ctx || !ctx->context || !out)) return E_PARAM;

    switch (ctx->type) {
        case KEY_RSA_2048:
            klen = 2048;
            break;
        case KEY_EC_P256:
            klen = 256;
            break;
        default:
            assert(0 && "unknow key_type");
    }

    bp = BIO_new(BIO_s_mem());
    if (unlikely(!bp)) return E_MEM;

    struct evp_key *ek = (struct evp_key *)(ctx->context);
    assert(ek->pkey);

    if (passwd && passwd->context) {
        struct symmetric_key *sk = (struct symmetric_key *)(passwd->context);
        cipher = sk->cipher;
        pass = sk->key;

        assert(cipher && passwd);
    }

    /**
     * @attention we choose the last argument to deliver the password due to the
     * `PEM_read_bio_PrivateKey` has no arguments 'kstr' and 'klen'
     */
    if (PEM_write_bio_PrivateKey(bp, ek->pkey, cipher, NULL, 0, NULL, (void *)pass) < 1) goto err;
    ret = BIO_read(bp, out, olen);
    if (ret > 10) goto out;

err:
    ret = E_EVP;
out:
    BIO_free(bp);
    return ret;
}

struct key_operation key_evp_operation = {&key_evp_encrypt, &key_evp_decrypt, &key_evp_sign,
                                          &key_evp_verify,  &get_evp_pubkey,  &get_evp_prikey};

void free_evp_key(void *k) {
    if (unlikely(!k)) return;

    struct evp_key *ek = (struct evp_key *)k;
    if (likely(ek->pkey)) {
        EVP_PKEY_free(ek->pkey);
        ek->pkey = NULL;
    }

    if (ek->param) {
        assert(ek->free_param);
        ek->free_param(ek->param);
        ek->param = NULL;
    }
}

int import_evp_pubkey(struct key_context *ctx, const enum key_type type, const uint8_t *k,
                      const int klen) {
    struct evp_key *ek = NULL;
    EVP_PKEY *ppkey = NULL;
    BIO *bp = NULL;
    int ret = E_OK;

    if (unlikely(!k || klen <= 10)) return E_PARAM;

    assert(ctx);
    if (!(ctx->context)) {
        ek = (struct evp_key *)calloc(1, sizeof(struct evp_key) + 1);
        if (unlikely((!ek))) goto err;
    } else {
        assert(ctx->context);
        ek = (struct evp_key *)(ctx->context);
    }

    bp = BIO_new_mem_buf(k, klen);
    if (unlikely((!bp) ? (ret = E_MEM) : 0)) goto err;

    ppkey = PEM_read_bio_PUBKEY(bp, &(ek->pkey), NULL, NULL);
    if (unlikely((!ppkey) ? (ret = E_EVP) : 0)) goto err;

    if (!(ctx->context)) {
        ctx->context = (void *)ek;

        // need to check the key type
        ctx->type = type;
        ctx->ops = &key_evp_operation;
        ctx->free_context = &free_evp_key;
    }

    BIO_free(bp);
    return ret;
err:
    BIO_free(bp);
    if (!(ctx->context)) free(ek);
    return ret;
}
int import_evp_prikey(struct key_context *ctx, const enum key_type type, const uint8_t *k,
                      const int klen, const struct key_context *passwd) {
    struct evp_key *ek = NULL;
    EVP_PKEY *ppkey = NULL;
    BIO *bp = NULL;
    const uint8_t *pass = NULL;
    int ret = E_OK;

    if (unlikely(!k || klen <= 10)) return E_PARAM;

    assert(ctx);
    if (!(ctx->context)) {
        ek = (struct evp_key *)calloc(1, sizeof(struct evp_key) + 1);
        if (unlikely((!ek))) goto err;
    } else {
        assert(ctx->context);
        ek = (struct evp_key *)(ctx->context);
    }

    bp = BIO_new_mem_buf(k, klen);
    if (unlikely((!bp) ? (ret = E_MEM) : 0)) goto err;

    if (passwd && passwd->context) {
        struct symmetric_key *sk = (struct symmetric_key *)(passwd->context);
        pass = sk->key;
    }

    ppkey = PEM_read_bio_PrivateKey(bp, &(ek->pkey), NULL, (void *)pass);
    if (unlikely((!ppkey) ? (ret = E_EVP) : 0)) goto err;

    if (!(ctx->context)) {
        ctx->context = (void *)ek;

        // need to check the key type
        ctx->type = type;
        ctx->ops = &key_evp_operation;
        ctx->free_context = &free_evp_key;
    }

    BIO_free(bp);
    return ret;
err:
    BIO_free(bp);
    if (!(ctx->context)) free(ek);
    return ret;
}

/*********************************RSA************************************/
struct rsa_param {
    int padding;
};

int set_rsa_optional_params(EVP_PKEY_CTX *ctx, void *ep) {
    int ret = E_OK;

    assert(ctx && ep);
    struct rsa_param *rp = (struct rsa_param *)ep;
    logger_trace("rsa padding: %d", rp->padding);
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, rp->padding) < 1) {
        ret = E_EVP;
        goto err;
    }

err:
    return ret;
}

int create_rsa_key(struct key_context *ctx, const enum key_type type) {
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    uint8_t primes = 2;
    int ret = E_OK;

    /* create rsa context */
    struct evp_key *ek = (struct evp_key *)malloc(sizeof(struct evp_key) + 1);
    struct rsa_param *rp = (struct rsa_param *)malloc(sizeof(struct rsa_param) + 1);
    if ((!ek || !rp) ? (ret = E_MEM) : 0) goto err;

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

    genctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!genctx) goto rsar;                                            /* Error occurred */
    if (EVP_PKEY_keygen_init(genctx) < 1) goto rsar;                   /* Error */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) < 1) goto rsar; /* Error */

    /* Generate key */
    if (EVP_PKEY_keygen(genctx, &pkey) < 1) goto rsar; /* free evp pkey context */

    EVP_PKEY_CTX_free(genctx);

    assert(ctx);
    rp->padding = RSA_PKCS1_PADDING;  // use pkcs1 padding in default

    ek->pkey = pkey;
    ek->param = (void *)rp;
    ek->set_optional_params = &set_rsa_optional_params;
    ek->free_param = &free;

    ctx->type = type;
    ctx->context = (void *)ek;
    ctx->ops = &key_evp_operation;
    ctx->free_context = &free_evp_key;
    return ret;

rsar:
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(pkey);
    ret = E_GENRSA;
err:
    free(ek);
    free(rp);
    return ret;
}

int set_rsa_padding_to_key_context(struct key_context *ctx, const int padding) {
    struct rsa_param *rp = NULL;

    if (unlikely(!ctx || !ctx->context)) return E_PARAM;
    if (unlikely(ctx->type <= KEY_RSA_1024 || ctx->type >= KEY_RSA_2048)) return E_PARAM;

    struct evp_key *ek = (struct evp_key *)(ctx->context);
    if (ek->param) {
        rp = (struct rsa_param *)(ek->param);

    } else {
        rp = (struct rsa_param *)malloc(sizeof(struct rsa_param) + 1);
        ek->param = (void *)rp;
    }

    rp->padding = padding;
    return E_OK;
}

const struct super_key_operation super_rsa_key_ops = {&create_rsa_key, &import_evp_pubkey,
                                                      &import_evp_prikey};
int init_rsa_key() {
    super_key_ops[KEY_RSA_1024] = &super_rsa_key_ops;
    super_key_ops[KEY_RSA_2048] = &super_rsa_key_ops;
    super_key_ops[KEY_RSA_4096] = &super_rsa_key_ops;

    logger_trace("init rsa key ok");
    return E_OK;
}

/********************************ECDSA***********************************/
int set_ec_optional_params(EVP_PKEY_CTX *ctx, void *ep) {
    int ret = E_OK;
    assert(ctx && ep);

err:
    return ret;
}

struct key_operation key_ec_operation = {
    NULL, NULL, &key_evp_sign, &key_evp_verify, &get_evp_pubkey, &get_evp_prikey};

int set_curve_name_by_key_type(EVP_PKEY_CTX *genctx, const enum key_type type) {
    int ret = E_OK;
    switch (type) {
        case KEY_EC_P256: {
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(genctx, NID_secp256k1) < 1) ret = E_GENEC;
        } break;
        default:
            ret = E_PARAM;
    }

err:
    return ret;
}

int create_ec_key(struct key_context *ctx, const enum key_type type) {
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = E_OK;

    /* create ec key context */
    struct evp_key *ek = (struct evp_key *)malloc(sizeof(struct evp_key) + 1);
    if (unlikely(!ek)) return E_MEM;

    genctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!genctx) goto err;
    if (EVP_PKEY_keygen_init(genctx) < 1) goto err;
    if ((ret = set_curve_name_by_key_type(genctx, type)) < 0) goto err;

    /* Generate key */
    if (EVP_PKEY_keygen(genctx, &pkey) < 1) goto err;

    EVP_PKEY_CTX_free(genctx);

    assert(ctx);
    ek->pkey = pkey;

    ek->param = NULL;
    ek->set_optional_params = &set_ec_optional_params;
    ek->free_param = &free;

    ctx->type = type;
    ctx->context = (void *)ek;
    ctx->ops = &key_ec_operation;
    ctx->free_context = &free_evp_key;
    return ret;

err:
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(pkey);
    ret = E_GENEC;
    return ret;
}

const struct super_key_operation super_ec_key_ops = {&create_ec_key, &import_evp_pubkey,
                                                     &import_evp_prikey};
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