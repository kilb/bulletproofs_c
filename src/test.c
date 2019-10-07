#include <stdio.h>
#include <stdlib.h>
#include "range_proof.h"
#include <openssl/ec.h>

#define try_or(x, error) \
    {                    \
        if (!(x))        \
        {                \
            goto error;  \
        }                \
    }

int test2()
{
    int n = 16;
    int bits = 64;
    int m = n * bits;
    BIGNUM *ss[n];
    BIGNUM *bb[n];
    EC_POINT *G[m];
    EC_POINT *H[m];
    EC_POINT *C[n];
    BIGNUM *top = NULL;
    EC_POINT *P = NULL;
    EC_GROUP *group = NULL;

    BN_CTX *ctx = NULL;

    RANGE_PROOF *proof = NULL;
    char *str = NULL;
    RANGE_PROOF *proof2 = NULL;



    for (int i = 0; i < n; ++i)
    {
        ss[i] = NULL;
        bb[i] = NULL;
        C[i] = NULL;
    }

    for (int i = 0; i < m; ++i)
    {
        G[i] = NULL;
        H[i] = NULL;
    }

    printf("Init:\n");
    try_or(ctx = BN_CTX_new(), error);
    try_or(group = EC_GROUP_gen(), error);

    try_or(top = BN_new(), error);
    try_or(P = EC_POINT_rnd_gen(group), error);

    try_or(BN_set_word(top, 1), error);
    try_or(BN_lshift(top, top, bits - 1), error);

    printf("generate rand:\n");
    for (int i = 0; i < n; ++i)
    {
        try_or(ss[i] = BN_rnd_gen(), error);
        try_or(bb[i] = BN_rnd_gen(), error);
        BN_mod(ss[i], ss[i], top, ctx);
    }

    printf("generate pedersen commit:\n");
    for (int i = 0; i < n; ++i)
    {
        try_or(C[i] = EC_POINT_new(group), error);
        try_or(pedersen_commit(group, C[i], P, ss[i], bb[i], ctx), error);
    }

    printf("generate G, H:\n");
    for (int i = 0; i < m; ++i)
    {
        try_or(G[i] = EC_POINT_rnd_gen(group), error);
        try_or(H[i] = EC_POINT_rnd_gen(group), error);
    }

    printf("begin generate proof:\n");
    try_or(proof = RANGE_PROOF_prove(group, (const EC_POINT **)G, (const EC_POINT **)H, P, ss, bb, bits, n), error);

    printf("generate proof: ok\n");

    try_or(RANGE_PROOF_verify(group, proof, (const EC_POINT **)G, (const EC_POINT **)H, (const EC_POINT **)C, P, bits, n), error);
    printf("verify proof: ok\n");

    try_or(str = range_proof_2_hex(group, proof), error);
    printf("convert proof to hex: ok\n");

    try_or(proof2 = hex_2_range_proof(group, str), error);
    printf("convert hex to proof: ok\n");

    try_or(RANGE_PROOF_verify(group, proof2, (const EC_POINT **)G, (const EC_POINT **)H, (const EC_POINT **)C, P, bits, n), error);
    printf("verify proof2: ok\n");

error:
    for (int i = 0; i < n; ++i)
    {
        BN_free(ss[i]);
        BN_free(bb[i]);
        EC_POINT_free(C[i]);
    }
    for (int i = 0; i < n; ++i)
    {
        EC_POINT_free(G[i]);
        EC_POINT_free(H[i]);
    }

    BN_free(top);
    EC_POINT_free(P);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    RANGE_PROOF_free(proof);
    RANGE_PROOF_free(proof2);
    free(str);

    return 0;
}

int test1()
{
    int n = 8;
    BIGNUM *a[n];
    BIGNUM *b[n];
    BIGNUM *ab;
    EC_POINT *G[n];
    EC_POINT *H[n];
    EC_POINT *Q;
    EC_POINT *P0;
    EC_POINT *P1;
    EC_POINT *P2;
    EC_GROUP *group = EC_GROUP_gen();
    BN_CTX *ctx;
    int ret;
    char *s = NULL;
    IP_PROOF *proof = NULL;
    IP_PROOF *proof2 = NULL;

    ctx = BN_CTX_new();
    const BIGNUM *order = EC_GROUP_get0_order(group);

    for (int i = 0; i < n; ++i)
    {
        a[i] = BN_rnd_gen();
        b[i] = BN_rnd_gen();
        G[i] = EC_POINT_rnd_gen(group);
        H[i] = EC_POINT_rnd_gen(group);
        if (!a[i] || !b[i] || !G[i] || !H[i])
        {
            goto error;
        }
    }

    Q = EC_POINT_rnd_gen(group);
    P0 = EC_POINT_new(group);
    P1 = EC_POINT_new(group);
    P2 = EC_POINT_new(group);
    ab = BN_new();

    EC_POINTs_mul(group, P0, NULL, n, (const EC_POINT **)G, (const BIGNUM **)a, ctx);
    EC_POINTs_mul(group, P1, NULL, n, (const EC_POINT **)H, (const BIGNUM **)b, ctx);
    inner_product(ab, (const BIGNUM **)a, (const BIGNUM **)b, order, ctx, n);
    EC_POINT_mul(group, P2, NULL, Q, ab, ctx);
    EC_POINT_add(group, P0, P0, P1, ctx);
    EC_POINT_add(group, P0, P0, P2, ctx);

    if (!Q || !P0 || !P1 || !P2)
    {
        goto error;
    }

    printf("begin:\n");
    proof = inner_product_prove((const EC_POINT **)G, (const EC_POINT **)H, Q, (const BIGNUM **)a, (const BIGNUM **)b, group, n);

    if (proof == NULL)
    {
        printf("proof is NULL\n");
    }

    ret = inner_product_verify(proof, (const EC_POINT **)G, (const EC_POINT **)H, Q, P0, group, n);

    printf("for valid P, the result is %d.\n", ret);

    ret = inner_product_verify(proof, (const EC_POINT **)G, (const EC_POINT **)H, Q, P1, group, n);

    printf("for invalid P, the result is %d.\n", ret);

    s = ip_proof_2_hex(group, proof);
    if (!s)
    {
        printf("convert proof to hex: fail\n");
    }

    proof2 = hex_2_ip_proof(group, s);
    if (!proof2)
    {
        printf("convert hex to proof: fail\n");
    }

    ret = inner_product_verify(proof2, (const EC_POINT **)G, (const EC_POINT **)H, Q, P0, group, n);
    if (ret)
    {
        printf("convert hex to proof: success\n");
    }

error:
    return 0;
}

int main()
{
    test1();
    printf("\n");
    test2();
}