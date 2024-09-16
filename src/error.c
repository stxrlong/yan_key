#include "error.h"

const char* get_err_msg(const int ret) {
    switch (ret) {
        case E_OK:
            return "success";

#define T(a, b, c) \
    case E_##b:    \
        return c;
            FOR_EACH_ERROR(T)
#undef T

        default:
            return "unknown error code";
    }
}