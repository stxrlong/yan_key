extern "C" {
#include "key.h"
#include "logger.h"
}

#include <gtest/gtest.h>

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

    const std::string plaintext = "test key";
    uint8_t out[256];
    int olen = 256;
    ret = encrypt_with_key(ctx, (uint8_t *)plaintext.c_str(), (int)plaintext.size(), out, &olen);
    ASSERT_EQ(ret, 0);

    uint8_t dec[256] = {0};
    int dlen = 256;
    ret = decrypt_with_key(ctx, out, olen, dec, &dlen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(dlen, 8);
    logger_info("plaintext: %s, decrypted: %s", plaintext.c_str(), dec);
}
}  // namespace test
