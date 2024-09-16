#include "key_com.h"

const char* get_key_type(const enum key_type type) {
    switch (type) {
#define T(a)      \
    case KEY_##a: \
        return #a;

        FOR_EACH_KEY_TYPE(T)
#undef T

        default:
            return "UNKNOWN KEY TYPE";
    }
}