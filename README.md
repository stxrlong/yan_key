YAN-KEY (under developing)

- [Overview](#overview)
- [Feature](#feature)
- [Build](#build)
- [Usage](#usage)
  - [key](#key)
  - [certificate](#certificate)

**Note**: I'm not a native speaker, if the following instruction is unclear, please feel relaxed to contact the auther '[stxr.long@gmail.com](stxr.long@gmail.com)'

## Overview

This is an easy used key operator library depends on the `OpenSSL`. I just put a shell on the basis of `OpenSSL`, so that you only need to understand the key usage through common sense. you don't need to know what are `EVP_PKEY` and `EVP_PKEY_CTX`, especially for those deep operations provided by `OpenSSL`.

## Feature

We support the following keys:

- AES with encryption
- RSA with encryption and signature
- ECC with signature

This project is under developing, more keys will be added soon, include the certification operations.

## Build

You can just copy the following files to your own project, and build with depending library `-lcrypto`, or you can build as follows:

```
mkdir build
cd build
cmake ..
```

## Usage

#### key

It's easy to use this library, you can refer to the test case under the directory `test/`, here We provide an example:

```
/* create a key context pointer, you need not to know what's in it */
struct key_context *ctx = NULL;
/* 
 * init the key context with key type
 * of course, you can import the existed key instead of creating a new one
 * 
 * please check the return value, 0 is ok, otherwise, failed
 */
int ret = create_key_context(&ctx, KEY_RSA_2048 /* choose what type you want to operate */);

/* now you can do encryption/decryption or sign/verify */
ret = encrypt_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, &olen);
ret = decrypt_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, &olen);

ret = sign_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, &olen);
ret = verify_with_key(ctx, (uint8_t *)plaintext, (int)strlen(plaintext), out, olen);
```

#### certificate

It's on the way developing