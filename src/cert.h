#ifndef __CRYPTO_CERT_H__
#define __CRYPTO_CERT_H__

#include <string.h>

#include "key.h"
#include "key_com.h"

struct cert_subject {
    char O[64];
    char OU[64];
    char S[64];
    char L[64];
    char CN[64];
};

struct cert_req_context;
struct cert_context;

/**
 * @attention you cannot operate the subject pointer once you set to cert request
 */
int create_cert_req_context(struct cert_req_context*, const enum key_type, struct cert_subject*);
int get_pubpem_from_cert_req_context(char*, const struct cert_req_context*);
int get_pripem_from_cert_req_context(char*, const struct cert_req_context*);

int issue_cert(struct cert_context*, struct cert_req_context*, const struct cert_context*);

int certpem_to_cert_context(struct cert_context*, const char*);
int set_pripem_to_cert_context(struct cert_context*, const char*);
int is_ca_cert(const struct cert_context*);

#endif