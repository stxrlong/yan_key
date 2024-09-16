

extern "C" {
#include "key.h"
}

#include <gtest/gtest.h>

int main(int argc, char *argv[]) {
    int ret = init_keys();
    if (ret < 0) return ret;

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
