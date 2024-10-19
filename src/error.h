#ifndef __ERROR_H__
#define __ERROR_H__

#define FOR_EACH_COM_ERROR(T)      \
    T(1, PARAM, "parameter error") \
    T(2, MEM, "out of memory")     \
    T(3, NOTIMPL, "not implement") \
    T(4, BUFLEN, "buffer len is not enough")

#define FOR_EACH_KEY_ERROR(T)                              \
    T(100, RAND, "generate rand number failed")            \
    T(101, ENCKEY, "please provide the password")          \
    T(150, GENAES, "generate/import aes key failed")       \
    T(151, AES, "encrypt/decrypt with aes failed")         \
    T(160, GENRSA, "generate rsa key failed")              \
    T(161, RSA, "create operator context with rsa failed") \
    T(170, GENEC, "generate ec key failed")                \
    T(171, EC, "create operator context with ec failed")   \
    T(200, EVP, "operator with asym key failed")           \
    T(201, SIGN, "sign with asym prikey failed")           \
    T(202, VERIFY, "verify with asym pubkey failed")

#define FOR_EACH_ERROR(T) \
    FOR_EACH_COM_ERROR(T) \
    FOR_EACH_KEY_ERROR(T)

enum ERROR_CODE {
    E_OK = 0,

#define T(a, b, c) E_##b = -a,
    FOR_EACH_ERROR(T)
#undef T
};

const char* get_err_msg(const int ret);

#endif