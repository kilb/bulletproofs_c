#ifndef INNER_PRODUCT
#define INNER_PRODUCT

#include <openssl/ec.h>

// proof for inner product
typedef struct INNER_PRODUCT_PROOF_st
{
    int n;
    EC_POINT **L;
    EC_POINT **R;
    BIGNUM *a;
    BIGNUM *b;
} IP_PROOF;

IP_PROOF *inner_product_prove(const EC_POINT *G_e[], const EC_POINT *H_e[], EC_POINT *Q, const BIGNUM *a_e[], const BIGNUM *b_e[], const EC_GROUP *group, int n);
int inner_product_verify(const IP_PROOF *proof, const EC_POINT **G, const EC_POINT **H, const EC_POINT *Q, const EC_POINT *P, const EC_GROUP *group, int n);

BIGNUM *BN_rnd_gen();
EC_POINT *EC_POINT_rnd_gen(EC_GROUP *group);
int inner_product(BIGNUM *r, const BIGNUM *a[], const BIGNUM *b[], const BIGNUM *order, BN_CTX *ctx, int n);
void IP_PROOF_free(IP_PROOF *proof);

int hash(unsigned char *out, const unsigned char *in, const size_t len);
int gen_hash(const EC_GROUP *ec_group, BIGNUM *out, const EC_POINT *L, const EC_POINT *R, const EC_POINT *Q, BN_CTX *ctx);
int BN_gen_hash(BIGNUM *out, const BIGNUM *a, const BIGNUM *b, const BIGNUM *c);
EC_GROUP *EC_GROUP_gen();

char *ip_proof_2_hex(const EC_GROUP* group, IP_PROOF *p);
IP_PROOF *hex_2_ip_proof(const EC_GROUP* group, const char *cs);

#endif