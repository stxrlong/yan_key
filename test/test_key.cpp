extern "C" {
#include "key.h"
#include "logger.h"
}

#include <gtest/gtest.h>

#include <string>

namespace test {
TEST(test_key, key_aes) {
    struct key_context *ctx = nullptr;
    int ret = create_key_context(&ctx, KEY_AES_256_CBC);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(ctx != nullptr);

    const std::string plaintext = "test key";
    uint8_t out[256];
    int olen = sizeof(out);
    ret = encrypt_with_key(ctx, (uint8_t *)plaintext.c_str(), (int)plaintext.size(), out, olen);
    ASSERT_EQ(ret, 16);
    olen = ret;

    uint8_t dec[64] = {0};
    int dlen = sizeof(dec);
    ret = decrypt_with_key(ctx, out, olen, dec, dlen);
    ASSERT_EQ(ret, 8);
    dlen = ret;
    logger_info("plaintext: %s, decrypted: %s", plaintext.c_str(), dec);

    // get  prikey without password
    uint8_t key[128] = {0};
    int klen = sizeof(key);
    ret = export_prikey(ctx, key, klen, NULL);
    ASSERT_TRUE(ret > 10);
    klen = ret;
    logger_info("get aes 256 key [len: %d]: \n%s", klen, key);

    // import prikey without password
    struct key_context *import_key = NULL;
    ret = import_prikey(&import_key, KEY_AES_256_CBC, key, klen, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(import_key);
    memset(dec, 0, sizeof(dec));
    dlen = sizeof(dec);
    ret = decrypt_with_key(ctx, out, olen, dec, dlen);
    ASSERT_EQ(ret, 8);
    dlen = ret;
    logger_info("decrypt with imported key(no passwd) ok, plaintext: %s, decrypted: %s",
                plaintext.c_str(), dec);

    // get prikey with password
    struct key_context *passwd = nullptr;
    ret = create_key_context(&passwd, KEY_AES_256_CBC);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(passwd != nullptr);
    logger_info("created passwd");
    memset(key, 0, sizeof(key));
    klen = sizeof(key);
    ret = export_prikey(ctx, key, klen, passwd);
    ASSERT_TRUE(ret > 10);
    klen = ret;
    logger_info("get aes 256 key with password [len: %d]: \n%s", klen, key);

    // import prikey with password
    import_key = NULL;  // ignore the memleak
    ret = import_prikey(&import_key, KEY_AES_256_CBC, key, klen, passwd);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(import_key);
    memset(dec, 0, sizeof(dec));
    dlen = sizeof(dec);
    ret = decrypt_with_key(ctx, out, olen, dec, dlen);
    ASSERT_EQ(ret, 8);
    dlen = ret;
    logger_info("decrypt with imported key(has passwd) ok, plaintext: %s, decrypted: %s",
                plaintext.c_str(), dec);
}

TEST(test_key, key_rsa) {
    struct key_context *ctx = nullptr;
    int ret = create_key_context(&ctx, KEY_RSA_2048);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(ctx != nullptr);

    const char *plaintext = "test key";
    uint8_t out[256];
    int olen = sizeof(out);
    ret = encrypt_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_TRUE(ret > 10);
    olen = ret;

    uint8_t dec[256] = {0};
    int dlen = sizeof(dec);
    ret = decrypt_with_key(ctx, out, olen, dec, dlen);
    ASSERT_EQ(ret, 8);
    dlen = ret;
    logger_info("plaintext: %s, decrypted: %s", plaintext, dec);
    // sign and verify
    memset(out, 0, sizeof(out));
    olen = sizeof(out);
    ret = sign_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 256);
    olen = ret;
    logger_info("plaintext: %s", plaintext);

    ret = verify_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 0);

    // get pubkey
    uint8_t key[2048] = {0};
    int klen = sizeof(key);
    ret = export_pubkey(ctx, key, klen);
    ASSERT_TRUE(ret > 0);
    klen = ret;
    logger_info("get rsa 2048 pubkey [len: %d]: \n%s", klen, key);

    // import pubkey
    struct key_context *import_ctx = nullptr;
    ret = import_pubkey(&import_ctx, KEY_RSA_2048, key, klen);
    ASSERT_EQ(ret, 0);
    logger_info("import rsa 2048 pubkey ok");

    ret = verify_with_key(import_ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 0);
    logger_info("verify by imported rsa 2048 pubkey ok");

    // get prikey
    memset(key, 0, sizeof(key));
    klen = sizeof(key);
    ret = export_prikey(ctx, key, klen, NULL);
    ASSERT_TRUE(ret > 0);
    klen = ret;
    logger_info("get rsa 2048 prikey [len: %d]: \n%s", klen, key);
}

TEST(test_key, key_ec) {
    struct key_context *ctx = nullptr;
    int ret = create_key_context(&ctx, KEY_EC_P256);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(ctx != nullptr);

    const char *plaintext = "test key";
    uint8_t out[256];
    int olen = sizeof(out);
    // sign and verify
    memset(out, 0, sizeof(out));
    olen = sizeof(out);
    ret = sign_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_TRUE(ret > 10);
    olen = ret;
    logger_info("plaintext: %s, sig: %d", plaintext, olen);

    ret = verify_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 0);

    // get pubkey and prikey
    uint8_t key[512] = {0};
    int klen = sizeof(key);
    ret = export_pubkey(ctx, key, klen);
    ASSERT_TRUE(ret > 10);
    klen = ret;
    logger_info("get ec p256 pubkey [len: %d]: \n%s", klen, key);

    struct key_context *passwd = nullptr;
    ret = create_key_context(&passwd, KEY_AES_256_CBC);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(passwd != nullptr);
    logger_info("created ec key password ok");

    memset(key, 0, sizeof(key));
    klen = sizeof(key);
    ret = export_prikey(ctx, key, klen, passwd);
    ASSERT_TRUE(ret > 10);
    klen = ret;
    logger_info("get ec p256 prikey with password [len: %d]: \n%s", klen, key);

    // import prikey
    struct key_context *import_ctx = nullptr;
    ret = import_prikey(&import_ctx, KEY_EC_P256, key, klen, passwd);
    ASSERT_EQ(ret, 0);
    logger_info("import ecc-p256 prikey with password ok");

    memset(out, 0, sizeof(out));
    olen = sizeof(out);
    ret = sign_with_key(import_ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_TRUE(ret > 10);
    olen = ret;
    logger_info("sign with imported ecc-p256 prikey ok");

    ret = verify_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 0);
    logger_info("verify with original ecc-p256 pubkey ok");
}
}  // namespace test
