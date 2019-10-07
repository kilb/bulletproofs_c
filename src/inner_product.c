#include "inner_product.h"
#include <stdlib.h>
#include <openssl/sm3.h>
#include <openssl/bn.h>
#include <openssl/sm2.h>

#define BN_fold(a, x0, x1, n, order, ctx, error)                                                                                                                                           \
    {                                                                                                                                                                                      \
        for (int i = 0; i < (n); ++i)                                                                                                                                                      \
        {                                                                                                                                                                                  \
            if (!BN_mod_mul((a)[i], (a)[i], (x0), (order), (ctx)) || !BN_mod_mul((a + n)[i], (a + n)[i], (x1), (order), (ctx)) || !BN_mod_add((a)[i], (a)[i], (a + n)[i], (order), (ctx))) \
            {                                                                                                                                                                              \
                goto error;                                                                                                                                                                \
            }                                                                                                                                                                              \
        }                                                                                                                                                                                  \
    }

#define EC_POINT_fold(a, x0, x1, n, group, ctx, error)                                                                                                                                                     \
    {                                                                                                                                                                                                      \
        for (int i = 0; i < (n); ++i)                                                                                                                                                                      \
        {                                                                                                                                                                                                  \
            if (!EC_POINT_mul((group), (a)[i], NULL, (a)[i], (x0), (ctx)) || !EC_POINT_mul((group), (a + n)[i], NULL, (a + n)[i], (x1), (ctx)) || !EC_POINT_add((group), (a)[i], (a)[i], (a + n)[i], ctx)) \
            {                                                                                                                                                                                              \
                goto error;                                                                                                                                                                                \
            }                                                                                                                                                                                              \
        }                                                                                                                                                                                                  \
    }

#define try_or(x, error) \
    {                    \
        if (!(x))        \
        {                \
            goto error;  \
        }                \
    }

EC_GROUP *EC_GROUP_gen()
{
    return EC_GROUP_new_by_curve_name(NID_sm2p256v1);
}

void ec_print(const EC_GROUP *group, EC_POINT *p)
{
    char *s = EC_POINT_point2hex(group, (const EC_POINT *)p, POINT_CONVERSION_COMPRESSED, NULL);
    printf("%s\n", s);
    free(s);
}

int hash(unsigned char *out, const unsigned char *in, const size_t len)
{
    // sm3 hash function
    sm3(in, len, out);

    return SM3_DIGEST_LENGTH;
}

// calculate hash
int gen_hash(const EC_GROUP *ec_group, BIGNUM *out, const EC_POINT *L, const EC_POINT *R, const EC_POINT *Q, BN_CTX *ctx)
{
    int m = 0, n = 0;
    unsigned char payload[300];
    unsigned char h[100];

    // convert point to string
    if (L)
    {
        if ((m = EC_POINT_point2oct(ec_group, L, POINT_CONVERSION_COMPRESSED, payload, 100, ctx)) == 0)
        {
            return 0;
        }

        n += m;
    }

    if (R)
    {
        if ((m = EC_POINT_point2oct(ec_group, R, POINT_CONVERSION_COMPRESSED, payload + n, 100, ctx)) == 0)
        {
            return 0;
        }

        n += m;
    }

    if (Q)
    {
        if ((m = EC_POINT_point2oct(ec_group, Q, POINT_CONVERSION_COMPRESSED, payload + n, 100, ctx)) == 0)
        {
            return 0;
        }

        n += m;
    }

    if (!(m = hash(h, payload, n)))
    {
        return 0;
    }

    // convert hash to big number
    if (BN_bin2bn(h, m, out) == NULL)
    {
        return 0;
    }

    return 1;
}

// calculate hash
int BN_gen_hash(BIGNUM *out, const BIGNUM *a, const BIGNUM *b, const BIGNUM *c)
{
    int m = 0, n = 0;
    unsigned char payload[300];
    unsigned char h[100];

    // convert point to string
    if (a)
    {
        if ((m = BN_bn2binpad(a, payload, 100)) == 0)
        {
            return 0;
        }
        n += m;
    }

    if (b)
    {
        if ((m = BN_bn2binpad(b, payload + n, 100)) == 0)
        {
            return 0;
        }
        n += m;
    }

    if (c)
    {
        if ((m = BN_bn2binpad(c, payload + n, 100)) == 0)
        {
            return 0;
        }
        n += m;
    }

    if (!(m = hash(h, payload, n)))
    {
        return 0;
    }

    // convert hash to big number
    if (BN_bin2bn(h, m, out) == NULL)
    {
        return 0;
    }

    return 1;
}

int log2d(int n)
{
    int i = -1;
    for (; n != 0; ++i)
    {
        n >>= 1;
    }

    return i;
}

int inner_product(BIGNUM *r, const BIGNUM *a[], const BIGNUM *b[], const BIGNUM *order, BN_CTX *ctx, int n)
{
    if (!r)
    {
        return 0;
    }
    BIGNUM *tmp = NULL;
    int success = 0;

    if (!(tmp = BN_new()))
    {
        goto error;
    }

    BN_zero(r);

    for (int i = 0; i < n; ++i)
    {
        if (!BN_mod_mul(tmp, a[i], b[i], order, ctx))
        {
            goto error;
        }
        if (!BN_mod_add(r, r, tmp, order, ctx))
        {
            goto error;
        }
    }

    success = 1;

error:
    BN_free(tmp);
    return success;
}

IP_PROOF *inner_product_prove(const EC_POINT *G_e[], const EC_POINT *H_e[], EC_POINT *Q, const BIGNUM *a_e[], const BIGNUM *b_e[], const EC_GROUP *group, int n)
{
    // n must be pow of 2.
    if (n <= 0 || ((n) & (n - 1)) != 0)
    {
        return NULL;
    }

    BN_CTX *ctx = NULL;
    if (!(ctx = BN_CTX_new()))
    {
        return NULL;
    }

    int m = log2d(n);

    IP_PROOF *proof = NULL;

    EC_POINT *G[n], *H[n];
    BIGNUM *a[n], *b[n];

    BIGNUM *cl = NULL;
    BIGNUM *cr = NULL;
    BIGNUM *x = NULL;
    BIGNUM *x_inv = NULL;

    EC_POINT *cl_Q = NULL;
    EC_POINT *al_Gr = NULL;
    EC_POINT *br_Hl = NULL;
    EC_POINT *ar_Gl = NULL;
    EC_POINT *bl_Hr = NULL;
    EC_POINT *cr_Q = NULL;

    //split
    const BIGNUM **al = (const BIGNUM **)a;
    const BIGNUM **bl = (const BIGNUM **)b;
    const EC_POINT **Gl = (const EC_POINT **)G;
    const EC_POINT **Hl = (const EC_POINT **)H;

    const BIGNUM *order;

    EC_POINT **L = (EC_POINT **)malloc(sizeof(EC_POINT *) * m);
    EC_POINT **R = (EC_POINT **)malloc(sizeof(EC_POINT *) * m);

    if (!L || !R)
    {
        goto error;
    }

    for (int i = 0; i < m; ++i)
    {
        L[i] = NULL;
        R[i] = NULL;
    }

    for (int i = 0; i < n; ++i)
    {
        G[i] = NULL;
        H[i] = NULL;
        a[i] = NULL;
        b[i] = NULL;
    }

    for (int i = 0; i < m; ++i)
    {
        try_or(L[i] = EC_POINT_new(group), error);
        try_or(R[i] = EC_POINT_new(group), error);
    }

    // copy
    for (int i = 0; i < n; ++i)
    {
        try_or(G[i] = EC_POINT_dup(G_e[i], group), error);
        try_or(H[i] = EC_POINT_dup(H_e[i], group), error);
        try_or(a[i] = BN_dup(a_e[i]), error);
        try_or(b[i] = BN_dup(b_e[i]), error);
    }

    try_or(order = EC_GROUP_get0_order(group), error);
    
    try_or(x = BN_new(), error);
    try_or(x_inv = BN_new(), error);
    try_or(cl = BN_new(), error);
    try_or(cr = BN_new(), error);

    try_or(cl_Q = EC_POINT_new(group), error);
    try_or(al_Gr = EC_POINT_new(group), error);
    try_or(br_Hl = EC_POINT_new(group), error);
    try_or(cr_Q = EC_POINT_new(group), error);
    try_or(ar_Gl = EC_POINT_new(group), error);
    try_or(bl_Hr = EC_POINT_new(group), error);

    for (int i = 0, k = n >> 1; i < m; ++i, k >>= 1)
    {
        const BIGNUM **ar = (const BIGNUM **)(a + k);
        const BIGNUM **br = (const BIGNUM **)(b + k);
        const EC_POINT **Gr = (const EC_POINT **)(G + k);
        const EC_POINT **Hr = (const EC_POINT **)(H + k);
        
        try_or(inner_product(cl, al, br, order, ctx, k), error);
        try_or(inner_product(cr, ar, bl, order, ctx, k), error);

        // L = <al, Gr> + <br, Hl> + [cl]Q
        try_or(EC_POINT_mul(group, cl_Q, NULL, Q, cl, ctx), error);
        try_or(EC_POINTs_mul(group, al_Gr, NULL, k, Gr, al, ctx), error);
        try_or(EC_POINTs_mul(group, br_Hl, NULL, k, Hl, br, ctx), error);
        try_or(EC_POINT_add(group, L[i], al_Gr, br_Hl, ctx), error);
        try_or(EC_POINT_add(group, L[i], L[i], cl_Q, ctx), error);

        // R = <ar, Gl> + <bl, Hr> + [cr]Q
        try_or(EC_POINT_mul(group, cr_Q, NULL, Q, cr, ctx), error);
        try_or(EC_POINTs_mul(group, ar_Gl, NULL, k, Gl, ar, ctx), error);
        try_or(EC_POINTs_mul(group, bl_Hr, NULL, k, Hr, bl, ctx), error);
        try_or(EC_POINT_add(group, R[i], ar_Gl, bl_Hr, ctx), error);
        try_or(EC_POINT_add(group, R[i], R[i], cr_Q, ctx), error);

        // gen x
        try_or(gen_hash(group, x, L[i], R[i], Q, ctx), error);

        // x^(-1)
        try_or(BN_mod_inverse(x_inv, x, order, ctx), error);

        // update a[0..k]
        BN_fold(a, x, x_inv, k, order, ctx, error);

        // update b[0..k]
        BN_fold(b, x_inv, x, k, order, ctx, error);

        // update G
        EC_POINT_fold(G, x_inv, x, k, group, ctx, error);

        // update H
        EC_POINT_fold(H, x, x_inv, k, group, ctx, error);
    }

    proof = (IP_PROOF *)malloc(sizeof(IP_PROOF));
    proof->L = L;
    proof->R = R;
    proof->a = a[0];
    proof->b = b[0];
    proof->n = m;

error:
    BN_free(cl);
    BN_free(cr);
    BN_free(x);
    BN_free(x_inv);
    EC_POINT_free(cl_Q);
    EC_POINT_free(al_Gr);
    EC_POINT_free(br_Hl);
    EC_POINT_free(ar_Gl);
    EC_POINT_free(bl_Hr);
    EC_POINT_free(cr_Q);

    for (int i = 0; i < n; ++i)
    {
        EC_POINT_free(G[i]);
        EC_POINT_free(H[i]);
    }

    for (int i = 1; i < n; ++i)
    {
        BN_free(a[i]);
        BN_free(b[i]);
    }

    if (!proof)
    {
        for (int i = 0; i < m; ++i)
        {
            EC_POINT_free(L[i]);
            EC_POINT_free(R[i]);
        }
        BN_free(a[0]);
        BN_free(b[0]);
    }

    return proof;
}

int b(int i, int j)
{
    int tmp = 1 << (j - 1);
    if (tmp & i)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

int inner_product_verify(const IP_PROOF *proof, const EC_POINT **G, const EC_POINT **H,
                         const EC_POINT *Q, const EC_POINT *P, const EC_GROUP *group, int n)
{
    // n must be pow of 2.
    if (n <= 0 || ((n) & (n - 1)) != 0 || proof == NULL)
    {
        return 0;
    }
    int m = log2d(n);
    int valid = 0;
    BIGNUM *s[n];
    BIGNUM *x[2][m];
    BIGNUM *ab = NULL;
    EC_POINT *G0 = NULL;
    EC_POINT *H0 = NULL;
    EC_POINT *Q0 = NULL;
    EC_POINT *L0 = NULL;
    EC_POINT *R0 = NULL;
    EC_POINT *P0 = NULL;
    EC_POINT *T0 = NULL;
    BN_CTX *ctx = NULL;
    // order of group
    const BIGNUM *order;

    for (int i = 0; i < n; ++i)
    {
        s[i] = NULL;
    }

    for (int i = 0; i < m; ++i)
    {
        x[0][i] = NULL;
        x[1][i] = NULL;
    }
    
    try_or(order = EC_GROUP_get0_order(group), error);
    try_or(ctx = BN_CTX_new(), error);

    try_or(ab = BN_new(), error);
    try_or(G0 = EC_POINT_new(group), error);
    try_or(H0 = EC_POINT_new(group), error);
    try_or(Q0 = EC_POINT_new(group), error);
    try_or(L0 = EC_POINT_new(group), error);
    try_or(R0 = EC_POINT_new(group), error);
    try_or(P0 = EC_POINT_new(group), error);
    try_or(T0 = EC_POINT_new(group), error);

    for (int i = 0; i < m; ++i)
    {
        try_or(x[0][i] = BN_new(), error);
        try_or(x[1][i] = BN_new(), error);
    }

    for (int i = 0; i < m; ++i)
    {
        // gen x
        try_or(gen_hash(group, x[0][i], proof->L[i], proof->R[i], Q, ctx), error);

        // x^(-1)
        try_or(BN_mod_inverse(x[1][i], x[0][i], order, ctx), error);
    }

    //si = x1^b(i,1) * x2^b(i,2) *...*xk^b(i,k)
    for (int i = 0; i < n; ++i)
    {
        try_or(s[i] = BN_dup(x[b(i, m)][0]), error);

        for (int j = 1; j < m; ++j)
        {
            try_or(BN_mod_mul(s[i], s[i], x[b(i, m - j)][j], order, ctx), error);
        }
    }

    // G0 = <s, G>
    try_or(EC_POINTs_mul(group, G0, NULL, n, (const EC_POINT **)G, (const BIGNUM **)s, ctx), error);

    //swap
    for (int i = 0; i < (n >> 1); ++i)
    {
        BIGNUM *tmp = s[i];
        s[i] = s[n - 1 - i];
        s[n - 1 - i] = tmp;
    }

    // H0 = <1/s, H>
    try_or(EC_POINTs_mul(group, H0, NULL, n, (const EC_POINT **)H, (const BIGNUM **)s, ctx), error);

    // G0 = aG0
    try_or(EC_POINT_mul(group, G0, NULL, G0, proof->a, ctx), error);

    // H0 = bH0
    try_or(EC_POINT_mul(group, H0, NULL, H0, proof->b, ctx), error);

    // ab = ab
    try_or(BN_mod_mul(ab, proof->a, proof->b, order, ctx), error);

    // Q0 = [ab]Q
    try_or(EC_POINT_mul(group, Q0, NULL, Q, ab, ctx), error);

    // xi = xi^(2)
    for (int i = 0; i < m; ++i)
    {
        try_or(BN_mod_mul(x[0][i], x[0][i], x[0][i], order, ctx), error);
        try_or(BN_mod_mul(x[1][i], x[1][i], x[1][i], order, ctx), error);
    }

    // L0 = <L, x>
    try_or(EC_POINTs_mul(group, L0, NULL, m, (const EC_POINT **)proof->L, (const BIGNUM **)x[0], ctx), error);

    // R0 = <R, x'>
    try_or(EC_POINTs_mul(group, R0, NULL, m, (const EC_POINT **)proof->R, (const BIGNUM **)x[1], ctx), error);

    // P0 = P + L0 + R0
    try_or(EC_POINT_add(group, P0, L0, R0, ctx), error);
    try_or(EC_POINT_add(group, P0, P0, P, ctx), error);

    // T0 = G0 + H0 + Q0
    try_or(EC_POINT_add(group, T0, G0, H0, ctx), error);
    try_or(EC_POINT_add(group, T0, T0, Q0, ctx), error);

    if (EC_POINT_cmp(group, T0, P0, ctx) == 0)
    {
        valid = 1;
    }

error:
    BN_CTX_free(ctx);
    BN_free(ab);
    EC_POINT_free(G0);
    EC_POINT_free(H0);
    EC_POINT_free(Q0);
    EC_POINT_free(L0);
    EC_POINT_free(R0);
    EC_POINT_free(P0);
    EC_POINT_free(T0);

    for (int i = 0; i < n; ++i)
    {
        BN_free(s[i]);
    }

    for (int i = 0; i < m; ++i)
    {
        BN_free(x[0][i]);
        BN_free(x[1][i]);
    }

    return valid;
}

BIGNUM *BN_rnd_gen()
{
    BIGNUM *rnd = NULL;
    if (!(rnd = BN_new()))
    {
        return NULL;
    }

    while (1)
    {
        if (!BN_rand(rnd, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        {
            free(rnd);
            return NULL;
        }
        if (!BN_is_zero(rnd))
        {
            break;
        }
    }

    return rnd;
}

EC_POINT *EC_POINT_rnd_gen(EC_GROUP *group)
{
    BIGNUM *rnd = NULL;
    EC_POINT *ec_rnd = NULL;

    if (!(ec_rnd = EC_POINT_new(group)))
    {
        return NULL;
    }

    if (!(rnd = BN_rnd_gen()))
    {
        EC_POINT_free(ec_rnd);
        return NULL;
    }

    if (!EC_POINT_mul(group, ec_rnd, rnd, NULL, NULL, NULL))
    {
        BN_free(rnd);
        EC_POINT_free(ec_rnd);
        return NULL;
    }

    BN_free(rnd);
    return ec_rnd;
}

void IP_PROOF_free(IP_PROOF *proof)
{
    if (proof)
    {
        for (int i = 0; i < proof->n; ++i)
        {
            EC_POINT_free(proof->L[i]);
            EC_POINT_free(proof->R[i]);
        }
        BN_free(proof->a);
        BN_free(proof->b);
    }
}