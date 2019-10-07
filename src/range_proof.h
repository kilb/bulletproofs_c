#include "inner_product.h"
#include <openssl/ec.h>

struct RANGE_PROOF_st
{
    EC_POINT *A;
    EC_POINT *S;
    EC_POINT *T1;
    EC_POINT *T2;
    BIGNUM *tx;
    BIGNUM *tr;
    BIGNUM *e;
    IP_PROOF *ip_proof;
};

typedef struct RANGE_PROOF_st RANGE_PROOF;

int pedersen_commit(const EC_GROUP *group, EC_POINT *r, EC_POINT *H,
                    BIGNUM *s, BIGNUM *rnd, BN_CTX *ctx);

RANGE_PROOF *RANGE_PROOF_prove(const EC_GROUP *group, const EC_POINT **G,
                               const EC_POINT **H, EC_POINT *P,
                               BIGNUM **ss, BIGNUM **bb, int bits, int n);

int RANGE_PROOF_verify(const EC_GROUP *group, const RANGE_PROOF *proof, const EC_POINT **G,
                       const EC_POINT **H, const EC_POINT **C, const EC_POINT *P, int bits, int n);