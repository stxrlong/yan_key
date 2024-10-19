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
    int olen = 0;
    ret = encrypt_with_key(ctx, (uint8_t *)plaintext.c_str(), (int)plaintext.size(), out, &olen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(olen, 16);

    uint8_t dec[64] = {0};
    int dlen = 0;
    ret = decrypt_with_key(ctx, out, olen, dec, &dlen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(dlen, 8);
    logger_info("plaintext: %s, decrypted: %s", plaintext.c_str(), dec);
}

TEST(test_key, key_rsa) {
    struct key_context *ctx = nullptr;
    int ret = create_key_context(&ctx, KEY_RSA_2048);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(ctx != nullptr);

    const char *plaintext = "test key";
    /**
     * @brief there is an error in encrypt with rsa, therefore, we need to add the following buffer
     */
    uint8_t buffer[1];
    uint8_t out[256];
    int olen = sizeof(out);
    ret = encrypt_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, &olen);
    ASSERT_EQ(ret, 0);

    uint8_t dec[256] = {0};
    int dlen = sizeof(dec);
    ret = decrypt_with_key(ctx, out, olen, dec, &dlen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(dlen, 8);
    logger_info("plaintext: %s, decrypted: %s", plaintext, dec);
    // sign and verify
    memset(out, 0, sizeof(out));
    olen = sizeof(out);
    ret = sign_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, &olen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(olen, 256);
    logger_info("plaintext: %s", plaintext);

    ret = verify_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 0);
}

TEST(test_key, key_ec) {
    struct key_context *ctx = nullptr;
    int ret = create_key_context(&ctx, KEY_EC_P256);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(ctx != nullptr);

    const char *plaintext = "test key";
    /**
     * @brief there is an error in encrypt with rsa, therefore, we need to add the following buffer
     */
    uint8_t buffer[1];
    uint8_t out[256];
    int olen = sizeof(out);
    // sign and verify
    memset(out, 0, sizeof(out));
    olen = sizeof(out);
    ret = sign_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, &olen);
    ASSERT_EQ(ret, 0);
    logger_info("plaintext: %s, sig: %d", plaintext, olen);

    ret = verify_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
    ASSERT_EQ(ret, 0);
}
}  // namespace test
