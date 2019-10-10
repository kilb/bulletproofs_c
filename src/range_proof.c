#include "range_proof.h"
#include <openssl/err.h>
#include <string.h>

#define BN_add_vec(r, x1, x2, n, order, ctx, error)                    \
    {                                                                  \
        for (int i = 0; i < (n); ++i)                                  \
        {                                                              \
            if (!BN_mod_add((r)[i], (x1)[i], (x2)[i], (order), (ctx))) \
            {                                                          \
                goto error;                                            \
            }                                                          \
        }                                                              \
    }

#define try_or(x, error) \
    {                    \
        if (!(x))        \
        {                \
            goto error;  \
        }                \
    }

#define print_bn(a)               \
    {                             \
        char *s = BN_bn2hex((a)); \
        printf("%s\n", s);        \
        free(s);                  \
    }

#define print_pt(a)                                                                 \
    {                                                                               \
        char *s = EC_POINT_point2hex(group, (a), POINT_CONVERSION_COMPRESSED, ctx); \
        printf("%s\n", s);                                                          \
        free(s);                                                                    \
    }

int pedersen_commit(const EC_GROUP *group, EC_POINT *r, EC_POINT *H, BIGNUM *s, BIGNUM *rnd, BN_CTX *ctx)
{
    int ex = (rnd == NULL);
    int success = 0;
    if (ex)
    {
        try_or(rnd = BN_rnd_gen(), error);
    }

    try_or(EC_POINT_mul(group, r, s, H, rnd, ctx), error);

    success = 1;

error:
    if (ex)
    {
        BN_free(rnd);
    }
    return success;
}

RANGE_PROOF *RANGE_PROOF_prove(const EC_GROUP *group, const EC_POINT **G,
                               const EC_POINT **H, EC_POINT *P,
                               BIGNUM **ss, BIGNUM **bb, int bits, int n)
{
    int m = bits * n;
    int ss_bits[m];
    BIGNUM *al[m];
    BIGNUM *ar[m];
    BIGNUM *sl[m];
    BIGNUM *sr[m];
    BIGNUM *ll[m];
    BIGNUM *rr[m];

    EC_POINT *H1[m];

    BIGNUM *exp_2 = NULL;
    BIGNUM *exp_y = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *alpha = NULL;
    BIGNUM *rho = NULL;
    BIGNUM *t0 = NULL;
    BIGNUM *t1 = NULL;
    BIGNUM *t2 = NULL;
    BIGNUM *t1r = NULL;
    BIGNUM *t2r = NULL;
    BIGNUM *b = NULL;
    BIGNUM *zz = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *z = NULL;
    BIGNUM *xx = NULL;
    BIGNUM *tx = NULL;
    BIGNUM *txr = NULL;
    BIGNUM *e = NULL;
    BIGNUM *w = NULL;
    BIGNUM *zero = NULL;
    BIGNUM *one = NULL;
    // -1
    BIGNUM *one_m = NULL;
    EC_POINT *A = NULL;
    EC_POINT *S = NULL;
    EC_POINT *EC_tmp = NULL;
    EC_POINT *yG = NULL;
    EC_POINT *T1 = NULL;
    EC_POINT *T2 = NULL;
    EC_POINT *Q = NULL;
    BN_CTX *ctx = NULL;

    IP_PROOF *ip_proof = NULL;
    RANGE_PROOF *proof = NULL;

    const BIGNUM *order;

    for (int i = 0; i < m; ++i)
    {
        al[i] = NULL;
        ar[i] = NULL;
        sl[i] = NULL;
        sr[i] = NULL;
        ll[i] = NULL;
        rr[i] = NULL;
        H1[i] = NULL;
    }

    try_or(ctx = BN_CTX_new(), error);
    try_or(order = EC_GROUP_get0_order(group), error);

    try_or(alpha = BN_rnd_gen(), error);
    try_or(rho = BN_rnd_gen(), error);
    try_or(t1r = BN_rnd_gen(), error);
    try_or(t2r = BN_rnd_gen(), error);

    try_or(x = BN_new(), error);
    try_or(y = BN_new(), error);
    try_or(z = BN_new(), error);
    try_or(zz = BN_new(), error);
    try_or(xx = BN_new(), error);
    try_or(exp_2 = BN_new(), error);
    try_or(exp_y = BN_new(), error);

    try_or(t0 = BN_new(), error);
    try_or(t1 = BN_new(), error);
    try_or(t2 = BN_new(), error);
    try_or(tx = BN_new(), error);
    try_or(txr = BN_new(), error);

    try_or(e = BN_new(), error);
    try_or(w = BN_new(), error);
    try_or(b = BN_new(), error);

    try_or(zero = BN_new(), error);
    try_or(one = BN_new(), error);
    try_or(one_m = BN_new(), error);

    try_or(tmp = BN_new(), error);

    try_or(A = EC_POINT_new(group), error);
    try_or(S = EC_POINT_new(group), error);
    try_or(yG = EC_POINT_new(group), error);
    try_or(EC_tmp = EC_POINT_new(group), error);
    try_or(T1 = EC_POINT_new(group), error);
    try_or(T2 = EC_POINT_new(group), error);
    try_or(Q = EC_POINT_new(group), error);

    try_or(BN_zero(zero), error);
    try_or(BN_set_word(one, 1), error);
    try_or(BN_mod_sub(one_m, order, one, order, ctx), error);

    for (int i = 0; i < m; ++i)
    {
        try_or(ll[i] = BN_new(), error);
        try_or(rr[i] = BN_new(), error);
        try_or(H1[i] = EC_POINT_new(group), error);
    }

    // get bits
    // ar = al - 1
    for (int i = 0, k = 0; i < n; ++i)
    {
        for (int j = 0; j < bits; ++j, ++k)
        {
            if ((ss_bits[k] = BN_is_bit_set(ss[i], j)))
            {
                try_or(al[k] = BN_dup(one), error);
                try_or(ar[k] = BN_dup(zero), error);
            }
            else
            {
                try_or(al[k] = BN_dup(zero), error);
                try_or(ar[k] = BN_dup(one_m), error);
            }
        }
    }

    try_or(EC_POINT_mul(group, A, NULL, P, alpha, ctx), error);
    try_or(EC_POINT_mul(group, S, NULL, P, rho, ctx), error);

    for (int i = 0; i < m; ++i)
    {
        try_or(sl[i] = BN_rnd_gen(), error);
        try_or(sr[i] = BN_rnd_gen(), error);
    }

    // set 0
    try_or(EC_POINT_set_to_infinity(group, EC_tmp), error);

    // A = <al, G> + <ar, H> + [alpha]P
    for (int i = 0; i < m; ++i)
    {
        if (ss_bits[i])
        {
            try_or(EC_POINT_add(group, A, A, G[i], ctx), error);
        }
        else
        {
            try_or(EC_POINT_add(group, EC_tmp, EC_tmp, H[i], ctx), error);
        }
    }

    // EC_tmp = -EC_tmp
    try_or(EC_POINT_mul(group, EC_tmp, NULL, EC_tmp, one_m, ctx), error);

    try_or(EC_POINT_add(group, A, EC_tmp, A, ctx), error);

    // S = <sl, G> + <sr, H> + [rho]P
    try_or(EC_POINTs_mul(group, EC_tmp, NULL, m, G, (const BIGNUM **)sl, ctx), error);
    try_or(EC_POINT_add(group, S, S, EC_tmp, ctx), error);
    try_or(EC_POINTs_mul(group, EC_tmp, NULL, m, H, (const BIGNUM **)sr, ctx), error);
    try_or(EC_POINT_add(group, S, S, EC_tmp, ctx), error);

    // y = hash(A, S)
    try_or(gen_hash(group, y, A, S, NULL, ctx), error);
    try_or(EC_POINT_mul(group, yG, y, NULL, NULL, ctx), error);
    // z = hash(yG)
    try_or(gen_hash(group, z, yG, NULL, NULL, ctx), error);

    //rename: l0 = al, l1 = sl, r0 = ar, r1 = sr
    // b = z^2*bb[0] + z^3*bb[1] + .. + z^(n+2)*bb[n]
    try_or(BN_set_word(exp_y, 1), error);
    try_or(BN_copy(zz, z), error);
    try_or(BN_zero(b), error);
    for (int i = 0, k = 0; i < n; ++i)
    {
        try_or(BN_mod_mul(zz, zz, z, order, ctx), error);

        try_or(BN_mod_mul(tmp, bb[i], zz, order, ctx), error);
        try_or(BN_mod_add(b, b, tmp, order, ctx), error);

        try_or(BN_copy(exp_2, zz), error);

        for (int j = 0; j < bits; ++j, ++k)
        {
            //l0 = al - z
            try_or(BN_mod_sub(al[k], al[k], z, order, ctx), error);

            //r0 = y^(i*j) * (ar + z) + z^2 * z^j * 2^j;
            try_or(BN_mod_add(ar[k], ar[k], z, order, ctx), error);
            try_or(BN_mod_mul(ar[k], ar[k], exp_y, order, ctx), error);
            try_or(BN_mod_add(ar[k], ar[k], exp_2, order, ctx), error);

            //r1 = exp_y * sr[i]
            try_or(BN_mod_mul(sr[k], sr[k], exp_y, order, ctx), error);

            //exp_y = exp_y * y
            try_or(BN_mod_mul(exp_y, exp_y, y, order, ctx), error);

            //exp_2 = 2 * exp_2
            try_or(BN_mod_add(exp_2, exp_2, exp_2, order, ctx), error);
        }
    }

    // t0 = <al, ar>
    try_or(inner_product(t0, (const BIGNUM **)al, (const BIGNUM **)ar, order, ctx, m), error);
    // t2 = <sl, sr>
    try_or(inner_product(t2, (const BIGNUM **)sl, (const BIGNUM **)sr, order, ctx, m), error);

    // t1 = <al+sl, ar+sr> - t0 - t2
    BN_add_vec(ll, al, sl, m, order, ctx, error);
    BN_add_vec(rr, ar, sr, m, order, ctx, error);
    try_or(inner_product(t1, (const BIGNUM **)ll, (const BIGNUM **)rr, order, ctx, m), error);
    try_or(BN_mod_sub(t1, t1, t0, order, ctx), error);
    try_or(BN_mod_sub(t1, t1, t2, order, ctx), error);

    // gen pedersen commit
    try_or(pedersen_commit(group, T1, P, t1, t1r, ctx), error);
    try_or(pedersen_commit(group, T2, P, t2, t2r, ctx), error);

    // x = hash(T1, T2)
    try_or(gen_hash(group, x, T1, T2, NULL, ctx), error);
    // xx = x * x
    try_or(BN_mod_mul(xx, x, x, order, ctx), error);
    // t1 = t1 * x
    try_or(BN_mod_mul(t1, t1, x, order, ctx), error);
    // t2 = t2 * x^2
    try_or(BN_mod_mul(t2, t2, xx, order, ctx), error);
    // tx = t0 + t1 + t2
    try_or(BN_mod_add(tx, t0, t1, order, ctx), error);
    try_or(BN_mod_add(tx, tx, t2, order, ctx), error);

    //txr = b + x*t1r + x^2*t2r
    try_or(BN_mod_mul(t1r, t1r, x, order, ctx), error);
    try_or(BN_mod_mul(t2r, t2r, xx, order, ctx), error);
    try_or(BN_mod_add(txr, b, t1r, order, ctx), error);
    try_or(BN_mod_add(txr, txr, t2r, order, ctx), error);

    // e = alpha + x*rho
    try_or(BN_mod_mul(rho, rho, x, order, ctx), error);
    try_or(BN_mod_add(e, rho, alpha, order, ctx), error);

    // w = hash(tx, txr, e)
    try_or(BN_gen_hash(w, tx, txr, e), error);
    // Q = [w]B
    try_or(EC_POINT_mul(group, Q, w, NULL, NULL, ctx), error);

    // sl = al+ sl*x, sr = ar + sr*x
    for (int i = 0; i < m; ++i)
    {
        try_or(BN_mod_mul(sl[i], sl[i], x, order, ctx), error);
        try_or(BN_mod_mul(sr[i], sr[i], x, order, ctx), error);
        try_or(BN_mod_add(sl[i], sl[i], al[i], order, ctx), error);
        try_or(BN_mod_add(sr[i], sr[i], ar[i], order, ctx), error);
    }

    // y = y^(-1)
    try_or(BN_mod_inverse(y, y, order, ctx), error);
    try_or(BN_set_word(exp_y, 1), error);
    for (int i = 0; i < m; ++i)
    {
        try_or(EC_POINT_mul(group, H1[i], NULL, H[i], exp_y, ctx), error);
        try_or(BN_mod_mul(exp_y, exp_y, y, order, ctx), error);
    }

    try_or(ip_proof = inner_product_prove((const EC_POINT **)G, (const EC_POINT **)H1, Q, (const BIGNUM **)sl, (const BIGNUM **)sr, group, m), error);

    try_or(proof = (RANGE_PROOF *)malloc(sizeof(RANGE_PROOF)), error);
    proof->A = A;
    proof->S = S;
    proof->T1 = T1;
    proof->T2 = T2;
    proof->tx = tx;
    proof->tr = txr;
    proof->e = e;
    proof->ip_proof = ip_proof;

error:
    for (int i = 0; i < m; ++i)
    {
        BN_free(al[i]);
        BN_free(ar[i]);
        BN_free(sl[i]);
        BN_free(sr[i]);
        BN_free(ll[i]);
        BN_free(rr[i]);
        EC_POINT_free(H1[i]);
    }

    BN_free(exp_2);
    BN_free(exp_y);
    BN_free(tmp);
    BN_free(alpha);
    BN_free(rho);
    BN_free(t0);
    BN_free(t1);
    BN_free(t2);
    BN_free(t1r);
    BN_free(t2r);
    BN_free(b);
    BN_free(zz);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(xx);
    BN_free(w);
    BN_free(zero);
    BN_free(one);
    // -1
    BN_free(one_m);
    EC_POINT_free(EC_tmp);
    EC_POINT_free(yG);
    EC_POINT_free(Q);
    BN_CTX_free(ctx);

    if (!proof)
    {
        BN_free(tx);
        BN_free(txr);
        BN_free(e);
        EC_POINT_free(A);
        EC_POINT_free(S);
        EC_POINT_free(T1);
        EC_POINT_free(T2);
        IP_PROOF_free(ip_proof);
    }

    return proof;
}

int RANGE_PROOF_verify(const EC_GROUP *group, const RANGE_PROOF *proof, const EC_POINT **G,
                       const EC_POINT **H, const EC_POINT **C, const EC_POINT *P, int bits, int n)
{
    int valid = 0;
    int m = n * bits;

    EC_POINT *H1[m];

    BIGNUM *x = NULL;
    BIGNUM *xx = NULL; // x^2
    BIGNUM *y = NULL;
    BIGNUM *z = NULL;
    BIGNUM *z_m = NULL; // -z
    BIGNUM *zz = NULL;  // z^2
    BIGNUM *w = NULL;
    BIGNUM *exp_y = NULL;
    BIGNUM *exp_2 = NULL;
    BIGNUM *exp_z = NULL;
    BIGNUM *sum_y = NULL;
    BIGNUM *sum_2 = NULL;
    BIGNUM *sum_z = NULL;
    BIGNUM *yz = NULL;
    BIGNUM *e_m = NULL;

    EC_POINT *yG = NULL;
    EC_POINT *V = NULL;
    EC_POINT *Q = NULL;
    EC_POINT *T1x = NULL;
    EC_POINT *T2x = NULL;
    EC_POINT *L = NULL;
    EC_POINT *P1 = NULL;
    EC_POINT *zH = NULL;
    EC_POINT *xS = NULL;
    EC_POINT *Gn = NULL;
    EC_POINT *Hn = NULL;
    EC_POINT *emP = NULL;

    EC_POINT *EC_tmp = NULL;

    BN_CTX *ctx = NULL;
    const BIGNUM *order;

    for (int i = 0; i < m; ++i)
    {
        H1[i] = NULL;
    }

    for (int i = 0; i < m; ++i)
    {
        try_or(H1[i] = EC_POINT_new(group), error);
    }

    try_or(ctx = BN_CTX_new(), error);
    try_or(order = EC_GROUP_get0_order(group), error);

    try_or(x = BN_new(), error);
    try_or(xx = BN_new(), error);
    try_or(y = BN_new(), error);
    try_or(z = BN_new(), error);
    try_or(z_m = BN_new(), error);
    try_or(zz = BN_new(), error);
    try_or(w = BN_new(), error);
    try_or(exp_y = BN_new(), error);
    try_or(exp_2 = BN_new(), error);
    try_or(exp_z = BN_new(), error);
    try_or(sum_y = BN_new(), error);
    try_or(sum_2 = BN_new(), error);
    try_or(sum_z = BN_new(), error);
    try_or(yz = BN_new(), error);
    try_or(e_m = BN_new(), error);

    try_or(yG = EC_POINT_new(group), error);
    try_or(V = EC_POINT_new(group), error);
    try_or(Q = EC_POINT_new(group), error);
    try_or(T1x = EC_POINT_new(group), error);
    try_or(T2x = EC_POINT_new(group), error);
    try_or(L = EC_POINT_new(group), error);
    try_or(P1 = EC_POINT_new(group), error);
    try_or(zH = EC_POINT_new(group), error);
    try_or(xS = EC_POINT_new(group), error);
    try_or(Gn = EC_POINT_new(group), error);
    try_or(Hn = EC_POINT_new(group), error);
    try_or(emP = EC_POINT_new(group), error);

    try_or(EC_tmp = EC_POINT_new(group), error);

    // y = hash(A, S)
    try_or(gen_hash(group, y, proof->A, proof->S, NULL, ctx), error);
    try_or(EC_POINT_mul(group, yG, y, NULL, NULL, ctx), error);
    // z = hash(yG)
    try_or(gen_hash(group, z, yG, NULL, NULL, ctx), error);
    try_or(BN_mod_sub(z_m, order, z, order, ctx), error);
    try_or(BN_mod_mul(zz, z, z, order, ctx), error);
    // x = hash(T1, T2)
    try_or(gen_hash(group, x, proof->T1, proof->T2, NULL, ctx), error);
    try_or(BN_mod_mul(xx, x, x, order, ctx), error);
    // w = hash(tx, txr, e)
    try_or(BN_gen_hash(w, proof->tx, proof->tr, proof->e), error);

    // Q = [w]B
    try_or(EC_POINT_mul(group, Q, w, NULL, NULL, ctx), error);

    try_or(BN_set_word(exp_y, 1), error);
    try_or(BN_zero(sum_y), error);

    for (int i = 0; i < m; ++i)
    {
        try_or(BN_mod_add(sum_y, sum_y, exp_y, order, ctx), error);
        try_or(BN_mod_mul(exp_y, exp_y, y, order, ctx), error);
    }

    // sum_2 = 1 + 2 + 4 + .. 2^(bits - 1)
    try_or(BN_zero(sum_2), error);
    try_or(BN_set_word(exp_2, 1), error);
    for (int i = 0; i < bits; ++i)
    {
        try_or(BN_mod_add(sum_2, sum_2, exp_2, order, ctx), error);
        try_or(BN_mod_add(exp_2, exp_2, exp_2, order, ctx), error);
    }

    // y = y^(-1)
    try_or(BN_mod_inverse(y, y, order, ctx), error);
    try_or(BN_set_word(exp_y, 1), error);
    for (int i = 0; i < m; ++i)
    {
        try_or(EC_POINT_mul(group, H1[i], NULL, H[i], exp_y, ctx), error);
        try_or(BN_mod_mul(exp_y, exp_y, y, order, ctx), error);
    }

    // V = [z^2]C[0]+[z^2]C[1]+..+[z^(2+n-1)]C[n-1]
    // sum_z = z^3 + z^4 + .. + z^(n+2)
    // zH = [z*2^n]H'
    try_or(EC_POINT_set_to_infinity(group, V), error);
    try_or(EC_POINT_set_to_infinity(group, zH), error);
    try_or(BN_zero(sum_z), error);
    try_or(BN_copy(exp_z, zz), error);
    for (int i = 0, k = 0; i < n; ++i)
    {
        try_or(EC_POINT_mul(group, EC_tmp, NULL, C[i], exp_z, ctx), error);
        try_or(EC_POINT_add(group, V, V, EC_tmp, ctx), error);

        try_or(BN_copy(exp_2, exp_z), error);
        for (int j = 0; j < bits; ++j, ++k)
        {
            try_or(EC_POINT_mul(group, EC_tmp, NULL, H1[k], exp_2, ctx), error);
            try_or(EC_POINT_add(group, zH, zH, EC_tmp, ctx), error);
            try_or(BN_mod_add(exp_2, exp_2, exp_2, order, ctx), error);
        }

        try_or(BN_mod_mul(exp_z, exp_z, z, order, ctx), error);
        try_or(BN_mod_add(sum_z, sum_z, exp_z, order, ctx), error);
    }

    // yz = (z-z^2)*sum_y - sum_z*sum_2
    try_or(BN_mod_sub(yz, z, zz, order, ctx), error);
    try_or(BN_mod_mul(yz, yz, sum_y, order, ctx), error);
    try_or(BN_mod_mul(sum_z, sum_z, sum_2, order, ctx), error);
    try_or(BN_mod_sub(yz, yz, sum_z, order, ctx), error);

    // T1x = yzG + xT1
    try_or(EC_POINT_mul(group, T1x, yz, proof->T1, x, ctx), error);
    // T2x = [x^2]T2
    try_or(EC_POINT_mul(group, T2x, NULL, proof->T2, xx, ctx), error);
    // V = V + T1x + T2x
    try_or(EC_POINT_add(group, V, V, T1x, ctx), error);
    try_or(EC_POINT_add(group, V, V, T2x, ctx), error);

    // L = [tx]G + [tr]P
    try_or(EC_POINT_mul(group, L, proof->tx, P, proof->tr, ctx), error);

    // L ?= V
    if (EC_POINT_cmp(group, L, V, ctx) != 0)
    {
        goto error;
    }

    // Gn = G[0] + G[1] + .. + G[m]
    // Hn = H[0] + H[1] + .. + H[m]
    try_or(EC_POINT_set_to_infinity(group, Gn), error);
    try_or(EC_POINT_set_to_infinity(group, Hn), error);
    for (int i = 0; i < m; ++i)
    {
        try_or(EC_POINT_add(group, Gn, Gn, G[i], ctx), error);
        try_or(EC_POINT_add(group, Hn, Hn, H[i], ctx), error);
    }

    try_or(EC_POINT_mul(group, xS, NULL, proof->S, x, ctx), error);
    try_or(EC_POINT_mul(group, Gn, NULL, Gn, z_m, ctx), error);
    try_or(EC_POINT_mul(group, Hn, NULL, Hn, z, ctx), error);
    try_or(BN_mod_sub(e_m, order, proof->e, order, ctx), error);
    try_or(EC_POINT_mul(group, emP, NULL, P, e_m, ctx), error);

    // P1 = ...
    try_or(EC_POINT_mul(group, P1, NULL, Q, proof->tx, ctx), error);

    try_or(EC_POINT_add(group, P1, P1, emP, ctx), error);
    try_or(EC_POINT_add(group, P1, P1, proof->A, ctx), error);
    try_or(EC_POINT_add(group, P1, P1, xS, ctx), error);

    try_or(EC_POINT_add(group, P1, P1, Gn, ctx), error);
    try_or(EC_POINT_add(group, P1, P1, Hn, ctx), error);

    try_or(EC_POINT_add(group, P1, P1, zH, ctx), error);

    try_or(inner_product_verify(proof->ip_proof, G, (const EC_POINT **)H1, Q, P1, group, m), error);
    valid = 1;

error:
    for (int i = 0; i < m; ++i)
    {
        EC_POINT_free(H1[i]);
    }

    BN_free(x);
    BN_free(xx); // x^2
    BN_free(y);
    BN_free(z);
    BN_free(z_m); // -z
    BN_free(zz);  // z^2
    BN_free(w);
    BN_free(exp_y);
    BN_free(exp_2);
    BN_free(exp_z);
    BN_free(sum_y);
    BN_free(sum_2);
    BN_free(sum_z);
    BN_free(yz);
    BN_free(e_m);

    EC_POINT_free(yG);
    EC_POINT_free(V);
    EC_POINT_free(Q);
    EC_POINT_free(T1x);
    EC_POINT_free(T2x);
    EC_POINT_free(L);
    EC_POINT_free(P1);
    EC_POINT_free(zH);
    EC_POINT_free(xS);
    EC_POINT_free(Gn);
    EC_POINT_free(Hn);
    EC_POINT_free(emP);

    EC_POINT_free(EC_tmp);

    BN_CTX_free(ctx);

    return valid;
}

void RANGE_PROOF_free(RANGE_PROOF *p)
{
    EC_POINT_free(p->A);
    EC_POINT_free(p->S);
    EC_POINT_free(p->T1);
    EC_POINT_free(p->T2);
    BN_free(p->tx);
    BN_free(p->tr);
    BN_free(p->e);
    IP_PROOF_free(p->ip_proof);
}

char *range_proof_2_hex(const EC_GROUP *group, RANGE_PROOF *p)
{
    if (!p)
    {
        return NULL;
    }

    int m = 0;
    char *a = NULL;
    char *s = NULL;
    char *t1 = NULL;
    char *t2 = NULL;
    char *tx = NULL;
    char *tr = NULL;
    char *e = NULL;
    char *ip = NULL;
    char *r = NULL;

    int na, ns, nt1, nt2, ntx, ntr, ne, nip;

    BN_CTX *ctx = NULL;

    try_or(ctx = BN_CTX_new(), error);

    try_or(tx = BN_bn2hex(p->tx), error);
    try_or(tr = BN_bn2hex(p->tr), error);
    try_or(e = BN_bn2hex(p->e), error);

    try_or(a = EC_POINT_point2hex(group, p->A, POINT_CONVERSION_COMPRESSED, ctx), error);
    try_or(s = EC_POINT_point2hex(group, p->S, POINT_CONVERSION_COMPRESSED, ctx), error);
    try_or(t1 = EC_POINT_point2hex(group, p->T1, POINT_CONVERSION_COMPRESSED, ctx), error);
    try_or(t2 = EC_POINT_point2hex(group, p->T2, POINT_CONVERSION_COMPRESSED, ctx), error);

    try_or(ip = ip_proof_2_hex(group, p->ip_proof), error);

    na = strlen(a) + 1;
    ns = strlen(s) + 1;
    nt1 = strlen(t1) + 1;
    nt2 = strlen(t2) + 1;
    ntx = strlen(tx) + 1;
    ntr = strlen(tr) + 1;
    ne = strlen(e) + 1;
    nip = strlen(ip) + 1;

    m = na + ns + nt1 + nt2 + ntx + ntr + ne + nip;

    try_or(r = (char *)malloc(sizeof(char) * m), error);
    
    m = 0;
    
    strcpy(r, tx);
    m += ntx;
    r[m - 1] = ':';

    strcpy(r + m, tr);
    m += ntr;
    r[m - 1] = ':';
    
    strcpy(r + m, e);
    m += ne;
    r[m - 1] = ':';

    strcpy(r + m, a);
    m += na;
    r[m - 1] = ':';
    
    strcpy(r + m, s);
    m += ns;
    r[m - 1] = ':';
    
    strcpy(r + m, t1);
    m += nt1;
    r[m - 1] = ':';
    
    strcpy(r + m, t2);
    m += nt2;
    r[m - 1] = ':';
    
    strcpy(r + m, ip);
    m += nip;
    r[m - 1] = '\0';

error:
    BN_CTX_free(ctx);
    free(a);
    free(s);
    free(t1);
    free(t2);
    free(tx);
    free(tr);
    free(e);
    free(ip);

    return r;
}

RANGE_PROOF *hex_2_range_proof(const EC_GROUP *group, const char *ch)
{
    if(!ch) {
        return NULL;
    }
    int len = strlen(ch) + 1;
    char h[len];
    strcpy(h, ch);
    
    char *pt[10];
    EC_POINT *A = NULL;
    EC_POINT *S = NULL;
    EC_POINT *T1 = NULL;
    EC_POINT *T2 = NULL;
    BIGNUM *tx = NULL;
    BIGNUM *tr = NULL;
    BIGNUM *e = NULL;
    IP_PROOF *ip = NULL;
    RANGE_PROOF *proof = NULL;
    BN_CTX *ctx = NULL;

    try_or(ctx = BN_CTX_new(), error);

    try_or(A = EC_POINT_new(group), error);
    try_or(S = EC_POINT_new(group), error);
    try_or(T1 = EC_POINT_new(group), error);
    try_or(T2 = EC_POINT_new(group), error);

    pt[0] = h;
    for (int i = 0, j = 1; j < 8; ++i)
    {
        if (h[i] == ':' || h[i] == '\0')
        {
            h[i] = '\0';
            pt[j] = h + i + 1;
            ++j;
        }
    }

    try_or(BN_hex2bn(&tx, pt[0]), error);
    try_or(BN_hex2bn(&tr, pt[1]), error);
    try_or(BN_hex2bn(&e, pt[2]), error);
    try_or(EC_POINT_hex2point(group, pt[3], A, ctx), error);
    try_or(EC_POINT_hex2point(group, pt[4], S, ctx), error);
    try_or(EC_POINT_hex2point(group, pt[5], T1, ctx), error);
    try_or(EC_POINT_hex2point(group, pt[6], T2, ctx), error);
    try_or(ip = hex_2_ip_proof(group, pt[7]), error);
    try_or(proof = (RANGE_PROOF *)malloc(sizeof(RANGE_PROOF)), error);

    proof->A = A;
    proof->S = S;
    proof->T1 = T1;
    proof->T2 = T2;
    proof->tx = tx;
    proof->tr = tr;
    proof->e = e;
    proof->ip_proof = ip;

error:
    BN_CTX_free(ctx);
    if (!proof)
    {
        BN_free(tx);
        BN_free(tr);
        BN_free(e);
        EC_POINT_free(A);
        EC_POINT_free(S);
        EC_POINT_free(T1);
        EC_POINT_free(T2);
        IP_PROOF_free(ip);
    }

    return proof;
}
