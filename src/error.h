#ifndef __ERROR_H__
#define __ERROR_H__

#define FOR_EACH_COM_ERROR(T)      \
    T(1, PARAM, "parameter error") \
    T(2, MEM, "out of memory")  \
    T(3, NOTIMPL, "not implement")

#define FOR_EACH_KEY_ERROR(T)                   \
    T(100, RAND, "generate rand number failed") \
    T(101, OPENSSLMEM, "out of memory in openssl") \
    T(150, AES, "encrypt/decrypt with aes failed")

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