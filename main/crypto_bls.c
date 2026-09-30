#include "cashu_suite.h"

#include <stdbool.h>
#include <string.h>

#include <blst.h>
#include <blst_aux.h>
#include <blst_mpi.h>
#include <mbedtls/sha256.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

/*
 * BLS12-381 crypto suite (keyset v3, version byte 0x02) over the vendored
 * blst component, per nuts PR #371:
 *
 *   - token points Y, B_, C_, C: compressed G1 (48 B); mint keys K:
 *     compressed G2 (96 B); scalars: 32-byte big-endian in (0, Fr order).
 *   - blinding is multiplicative: B_ = r*Y with Y = hash_to_G1(secret);
 *     unblinding C = r^-1 * C_. The mint key plays no role in unblinding
 *     (unlike secp's C = C_ - r*K), so unblind ignores K.
 *   - NUT-12 DLEQ is abolished: verification is the intrinsic pairing check
 *     e(C, g2) == e(Y, K), exposed through verify_proofs and batched over
 *     all n proofs via the Cashu_BLS_Batch_v1 Fiat-Shamir transcript.
 *
 * Every operation runs inside a blst_hw_acquire()/release() window so the
 * C3's RSA/MPI peripheral accelerates the field arithmetic (~4x); on other
 * targets those are no-ops and blst computes in software.
 */

/* NUT-00: hash-to-curve DST for the v3 G1 random-oracle suite. */
static const unsigned char DST[] = "CASHU_BLS12_381_G1_XMD:SHA-256_SSWU_RO_";
#define DST_LEN (sizeof(DST) - 1)

/* NUT-00: Fiat-Shamir transcript DST for batch verification. */
static const unsigned char BATCH_DST[] = "Cashu_BLS_Batch_v1";
#define BATCH_DST_LEN (sizeof(BATCH_DST) - 1)

#define G1_LEN 48
#define G2_LEN 96

/* BLS12-381 Fr order, big-endian. A 32-byte value is a valid scalar iff
 * 0 < OS2IP(x) < this, compared on the raw bytes: blst_scalar_from_be_bytes
 * REDUCES out-of-range inputs (reporting success), so its return value
 * cannot serve as the range check. */
static const unsigned char FR_ORDER_BE[32] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

static int be_lt(const unsigned char a[32], const unsigned char b[32])
{
    for (int i = 0; i < 32; i++) {
        if (a[i] != b[i])
            return a[i] < b[i];
    }
    return 0;
}

/* 32 big-endian bytes -> blst_scalar, rejecting 0 and values >= Fr order. */
static int scalar_from_be_checked(blst_scalar *out, const unsigned char be[32])
{
    int nonzero = 0;
    for (int i = 0; i < 32; i++)
        if (be[i]) { nonzero = 1; break; }
    if (!nonzero || !be_lt(be, FR_ORDER_BE))
        return 0;
    blst_scalar_from_be_bytes(out, be, 32);
    return 1;
}

static void hash_to_g1(blst_p1 *out, const unsigned char *msg, size_t len)
{
    blst_hash_to_g1(out, msg, len, DST, DST_LEN, NULL, 0);
}

/* blst_p1_mult takes the scalar as little-endian bytes. */
static void p1_mul(blst_p1 *out, const blst_p1 *p, const blst_scalar *s)
{
    unsigned char le[32];
    blst_lendian_from_scalar(le, s);
    blst_p1_mult(out, p, le, 256);
}

/* Full NUT-00 point validation: canonical encoding + on-curve (enforced by
 * uncompress), identity rejection, prime-order-subgroup membership (rejects
 * cofactor components — the Lim-Lee small-subgroup defense). */
static int validate_g1(blst_p1_affine *out, const unsigned char comp[G1_LEN])
{
    if (blst_p1_uncompress(out, comp) != BLST_SUCCESS)
        return 0;
    if (blst_p1_affine_is_inf(out))
        return 0;
    if (!blst_p1_affine_in_g1(out))
        return 0;
    return 1;
}

static int validate_g2(blst_p2_affine *out, const unsigned char comp[G2_LEN])
{
    if (blst_p2_uncompress(out, comp) != BLST_SUCCESS)
        return 0;
    if (blst_p2_affine_is_inf(out))
        return 0;
    if (!blst_p2_affine_in_g2(out))
        return 0;
    return 1;
}

/* --------------------------------------------------------------------------
 * Suite operations
 * ------------------------------------------------------------------------ */

static int bls_blind(void *ctx,
                     const unsigned char *secret, size_t secret_len,
                     const unsigned char *r, size_t r_len,
                     unsigned char *B_out, size_t *B_out_len)
{
    (void)ctx;
    if (r_len != 32 || !B_out_len || *B_out_len < G1_LEN)
        return 0;
    blst_scalar r_s;
    if (!scalar_from_be_checked(&r_s, r))
        return 0; /* r == 0 or >= Fr order: caller must supply a valid scalar */

    blst_hw_acquire();
    blst_p1 Y, B_;
    hash_to_g1(&Y, secret, secret_len);
    p1_mul(&B_, &Y, &r_s);
    blst_p1_compress(B_out, &B_);
    blst_hw_release();

    *B_out_len = G1_LEN;
    return 1;
}

static int bls_unblind(void *ctx,
                       const unsigned char *C_, size_t C__len,
                       const unsigned char *r, size_t r_len,
                       const unsigned char *K, size_t K_len,
                       unsigned char *C_out, size_t *C_out_len)
{
    (void)ctx;
    (void)K; (void)K_len; /* BLS unblinding is C = r^-1 * C_; K plays no role */
    if (C__len != G1_LEN || r_len != 32 || !C_out_len || *C_out_len < G1_LEN)
        return 0;
    blst_scalar r_s;
    if (!scalar_from_be_checked(&r_s, r))
        return 0;

    int ok = 0;
    blst_hw_acquire();

    blst_p1_affine C_aff;
    if (validate_g1(&C_aff, C_)) { /* attacker-visible input: full validation */
        blst_fr r_fr, r_inv_fr;
        blst_scalar r_inv;
        blst_fr_from_scalar(&r_fr, &r_s);
        blst_fr_inverse(&r_inv_fr, &r_fr);
        blst_scalar_from_fr(&r_inv, &r_inv_fr);

        blst_p1 C_pt, C_res;
        blst_p1_from_affine(&C_pt, &C_aff);
        p1_mul(&C_res, &C_pt, &r_inv);
        blst_p1_compress(C_out, &C_res);
        *C_out_len = G1_LEN;
        ok = 1;
    }

    blst_hw_release();
    return ok;
}

/* Derive the per-proof Fiat-Shamir weight w_i by rejection sampling:
 * first SHA256(challenge || u32_BE(i) || u32_BE(ctr)), ctr = 0,1,...,
 * whose value lies in (0, Fr order). */
static void derive_batch_weight(blst_scalar *w, const unsigned char challenge[32],
                                uint32_t i)
{
    unsigned char buf[40];
    memcpy(buf, challenge, 32);
    buf[32] = (unsigned char)(i >> 24);
    buf[33] = (unsigned char)(i >> 16);
    buf[34] = (unsigned char)(i >> 8);
    buf[35] = (unsigned char)i;
    for (uint32_t ctr = 0;; ctr++) {
        buf[36] = (unsigned char)(ctr >> 24);
        buf[37] = (unsigned char)(ctr >> 16);
        buf[38] = (unsigned char)(ctr >> 8);
        buf[39] = (unsigned char)ctr;
        unsigned char h[32];
        blst_sha256(h, buf, 40);
        if (scalar_from_be_checked(w, h))
            return;
    }
}

/* Pairings held per multi-miller call. Within one blst_miller_loop_n the
 * expensive fp12 accumulator squarings are shared across all pairings (the
 * spec's "single multi-miller loop" SHOULD); chunking bounds the stack.
 * Each slot costs ~0.7 KB: our affine copies (288 B) plus blst's internal
 * per-pair G2 accumulator VLA and line temporaries — chunks of 8 left only
 * 1.7 KB of console-stack margin. 4 keeps ~90% of the sharing (the saving
 * scales with sum(len-1)/n) at half the stack. */
#define MILLER_CHUNK 4

static void miller_flush(blst_fp12 *acc,
                         const blst_p2_affine *const qs[],
                         const blst_p1_affine *const ps[],
                         size_t len)
{
    if (len == 0)
        return;
    blst_fp12 ml;
    blst_miller_loop_n(&ml, qs, ps, len);
    blst_fp12_mul(acc, acc, &ml);
}

/*
 * NUT-00 batch verification:
 *
 *   e( sum_i w_i*C_i , g2 ) == prod_i e( w_i*Y_i , K_i )
 *
 * folded as  e( -sum_i w_i*C_i , g2 ) * prod_i e( w_i*Y_i , K_i ) == 1,
 * evaluated in chunked multi-miller loops under one final exponentiation.
 * n == 1 degenerates to the plain pairing check with w = 1 (the weight is
 * skipped entirely) — a single 2-pair multi-miller.
 *
 * The spec groups the right side by distinct mint key — but every AMOUNT has
 * a distinct key within a keyset (NUT-01 requires it), so a typical token's
 * keys are nearly all distinct and grouping saves close to nothing while
 * needing per-group accumulators. Per-proof pairs are constant-memory for
 * any batch size and compute the identical GT product; the last validated K
 * is cached so repeated denominations skip re-validation.
 *
 * The transcript challenge is streamed through mbedTLS SHA-256 so batches of
 * any size use constant memory; weights are consumed as they are derived.
 */
static int bls_verify_proofs(void *ctx, size_t n,
                             const unsigned char *Ks,
                             const unsigned char *Cs,
                             const unsigned char *const *secrets,
                             const size_t *secret_lens)
{
    (void)ctx;
    if (n == 0)
        return 1;
    if (!Ks || !Cs || !secrets || !secret_lens)
        return 0;

    /* challenge = SHA256(BATCH_DST || (C_i || K_i || u32_BE(len) || secret_i)...) */
    unsigned char challenge[32];
    if (n > 1) {
        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        if (mbedtls_sha256_starts(&sha, 0) != 0) {
            mbedtls_sha256_free(&sha);
            return 0;
        }
        int hash_ok = mbedtls_sha256_update(&sha, BATCH_DST, BATCH_DST_LEN) == 0;
        for (size_t i = 0; hash_ok && i < n; i++) {
            unsigned char len_be[4] = {
                (unsigned char)(secret_lens[i] >> 24),
                (unsigned char)(secret_lens[i] >> 16),
                (unsigned char)(secret_lens[i] >> 8),
                (unsigned char)(secret_lens[i]),
            };
            hash_ok = mbedtls_sha256_update(&sha, Cs + i * G1_LEN, G1_LEN) == 0 &&
                      mbedtls_sha256_update(&sha, Ks + i * G2_LEN, G2_LEN) == 0 &&
                      mbedtls_sha256_update(&sha, len_be, 4) == 0 &&
                      mbedtls_sha256_update(&sha, secrets[i], secret_lens[i]) == 0;
        }
        if (hash_ok)
            hash_ok = mbedtls_sha256_finish(&sha, challenge) == 0;
        mbedtls_sha256_free(&sha);
        if (!hash_ok)
            return 0;
    }

    int ok = 0;
    blst_hw_acquire();

    /* One pass: validate C_i, accumulate sum_C += w_i*C_i in G1, and queue
     * the (K_i, w_i*Y_i) pair for the chunked multi-miller product. */
    blst_p2_affine k_aff;
    const unsigned char *k_valid = NULL; /* last validated K (into Ks) */
    blst_p1 sum_c;
    blst_fp12 acc = *blst_fp12_one();
    blst_p2_affine chunk_q[MILLER_CHUNK];
    blst_p1_affine chunk_p[MILLER_CHUNK];
    const blst_p2_affine *chunk_qp[MILLER_CHUNK];
    const blst_p1_affine *chunk_pp[MILLER_CHUNK];
    size_t chunk_len = 0;

    for (size_t i = 0; i < n; i++) {
        blst_p1_affine c_aff;
        if (!validate_g1(&c_aff, Cs + i * G1_LEN))
            goto out;

        blst_scalar w;
        if (n > 1)
            derive_batch_weight(&w, challenge, (uint32_t)i);

        blst_p1 c_pt, wc;
        blst_p1_from_affine(&c_pt, &c_aff);
        if (n > 1)
            p1_mul(&wc, &c_pt, &w);
        else
            wc = c_pt;
        if (i == 0)
            sum_c = wc;
        else
            blst_p1_add(&sum_c, &sum_c, &wc);

        blst_p1 y, wy;
        hash_to_g1(&y, secrets[i], secret_lens[i]);
        if (n > 1)
            p1_mul(&wy, &y, &w);
        else
            wy = y;

        const unsigned char *k_comp = Ks + i * G2_LEN;
        if (!k_valid || memcmp(k_valid, k_comp, G2_LEN) != 0) {
            if (!validate_g2(&k_aff, k_comp))
                goto out;
            k_valid = k_comp;
        }

        chunk_q[chunk_len] = k_aff; /* copy: k_aff is a reused cache slot */
        blst_p1_to_affine(&chunk_p[chunk_len], &wy);
        chunk_qp[chunk_len] = &chunk_q[chunk_len];
        chunk_pp[chunk_len] = &chunk_p[chunk_len];
        if (++chunk_len == MILLER_CHUNK) {
            miller_flush(&acc, chunk_qp, chunk_pp, chunk_len);
            chunk_len = 0;
        }

        /* A 32-proof batch on the software BLS path can otherwise keep the
         * console task runnable for longer than the idle-task watchdog window.
         * Yield only between complete proof contributions; all accumulator and
         * hardware-lock invariants remain unchanged. */
        vTaskDelay(1);
    }

    {
        /* Fold the left side into the product as e(-sum_C, g2) and check
         * the whole thing final-exponentiates to one. */
        blst_p1_cneg(&sum_c, true);
        chunk_q[chunk_len] = *blst_p2_affine_generator();
        blst_p1_to_affine(&chunk_p[chunk_len], &sum_c);
        chunk_qp[chunk_len] = &chunk_q[chunk_len];
        chunk_pp[chunk_len] = &chunk_p[chunk_len];
        chunk_len++;
        miller_flush(&acc, chunk_qp, chunk_pp, chunk_len);

        /* The final exponentiation is another long indivisible primitive. */
        vTaskDelay(1);

        blst_fp12 gt;
        blst_final_exp(&gt, &acc);
        ok = blst_fp12_is_one(&gt) ? 1 : 0;
    }

out:
    blst_hw_release();
    return ok;
}

/* NUT-13 v3 secret derivation: identical to v2 — the raw 32 HMAC bytes. */
static int bls_derive_secret(const unsigned char *seed, size_t seed_len,
                             const char *keyset_id, uint32_t counter,
                             unsigned char *secret_out)
{
    return cashu_nut13_hmac(seed, seed_len, keyset_id, counter, 0x00,
                            NULL, 0, secret_out);
}

/* NUT-13 v3 blinding factor: rejection sampling against the Fr order (a
 * modular reduction would bias ~7.5% since Fr order is ~0.45*2^256). The
 * KDF message appends u32_BE(attempt), present from attempt 0. ~45%
 * acceptance per attempt; 64 attempts bounds p(fail) around 2^-55. */
static int bls_derive_r(const unsigned char *seed, size_t seed_len,
                        const char *keyset_id, uint32_t counter,
                        unsigned char *r_out)
{
    for (uint32_t attempt = 0; attempt < 64; attempt++) {
        unsigned char suffix[4] = {
            (unsigned char)(attempt >> 24), (unsigned char)(attempt >> 16),
            (unsigned char)(attempt >> 8), (unsigned char)attempt,
        };
        unsigned char x[32];
        if (!cashu_nut13_hmac(seed, seed_len, keyset_id, counter, 0x01,
                              suffix, 4, x))
            return 0;
        int nonzero = 0;
        for (int i = 0; i < 32; i++)
            if (x[i]) { nonzero = 1; break; }
        if (nonzero && be_lt(x, FR_ORDER_BE)) {
            memcpy(r_out, x, 32);
            return 1;
        }
    }
    return 0;
}

const cashu_suite_t cashu_suite_bls = {
    .version_byte = 0x02,
    .name = "bls12_381",
    .point_len = G1_LEN,    /* compressed G1: Y, B_, C_, C */
    .mint_key_len = G2_LEN, /* compressed G2: mint keys K  */
    .scalar_len = 32,
    .can_mint = 1,
    .has_dleq = 0,          /* NUT-12 does not apply to v3 — pairing verify instead */
    .blind = bls_blind,
    .unblind = bls_unblind,
    .verify_dleq = NULL,
    .verify_dleq_unblinded = NULL,
    .verify_proofs = bls_verify_proofs,
    .derive_secret = bls_derive_secret,
    .derive_r = bls_derive_r,
};
