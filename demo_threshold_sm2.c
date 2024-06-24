/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "testutil.h"
#include "bench.h"

// 多进程测试运行最大测试
#define MAX_SIZE 100000

#ifndef OPENSSL_NO_SM2_THRESHOLD

#include <openssl/sm2_threshold.h>

/* These values are from GM/T 0003.2-2012 standard */
static const char *userid = "ALICE123@YAHOO.COM";
static const char *message = "message digest";

static int ret = 0;
static int msg_len = 14;
static EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
static EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL, *temp_key = NULL;
static EVP_MD_CTX *mctx = NULL;
static EVP_PKEY_CTX *pctx = NULL;
static unsigned char *sigbuf = NULL, *final_sig = NULL;
static size_t siglen, final_siglen, dlen;
static unsigned char digest[EVP_MAX_MD_SIZE];

static unsigned char *sigbuf_signtest[MAX_SIZE], *final_sig_signtest[MAX_SIZE];
static size_t siglen_signtest[MAX_SIZE], final_siglen_signtest[MAX_SIZE], dlen;

BIGNUM *w;
EC_POINT *T1, *T2;
unsigned char *ct, *pt;
size_t pt_len, outlen;

static int test_sm2_threshold_keygen(void)
{
    int ret = 0;
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    EVP_PKEY *pubkey1 = NULL, *pubkey2 = NULL;
    EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;

    if (!TEST_ptr(key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")) || !TEST_ptr(key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    // pubkey1 = [d1^-1]G, pubkey2 = [d2^-1]G,
    if (!TEST_ptr(pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1)) || !TEST_ptr(pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)))
        goto err;

    if (!TEST_ptr(complete_key1 =
                      SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2)) ||
        !TEST_ptr(complete_key2 =
                      SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)))
        goto err;

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(pubkey1);
    EVP_PKEY_free(pubkey2);
    EVP_PKEY_free(complete_key1);
    EVP_PKEY_free(complete_key2);

    return ret;
}

static int test_sm2_threshold_sign(int id)
{
    if (!TEST_ptr(key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")) || !TEST_ptr(key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    if (!TEST_ptr(pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1)) || !TEST_ptr(pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)))
        goto err;

    if (!TEST_ptr(complete_key1 =
                      SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2)) ||
        !TEST_ptr(complete_key2 =
                      SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)))
        goto err;

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    /* Test SM2 threshold sign with id */
    // 协同签名
    if (!TEST_ptr(temp_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;
    if (id == 0)
    {
        if (!TEST_true(SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(),
                                                   (const uint8_t *)userid,
                                                   strlen(userid),
                                                   (const uint8_t *)message,
                                                   msg_len,
                                                   digest, &dlen)) ||
            !TEST_true(SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen,
                                           &sigbuf, &siglen)) ||
            !TEST_true(SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen,
                                           &final_sig, &final_siglen)))
            goto err;

        if (!TEST_ptr(mctx = EVP_MD_CTX_new()) || !TEST_ptr(pctx = EVP_PKEY_CTX_new(complete_key1, NULL)))
            goto err;

        EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

        if (!TEST_true(EVP_PKEY_CTX_set1_id(pctx, userid, strlen(userid))))
            goto err;

        if (!TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL,
                                            complete_key1)) ||
            !TEST_true(EVP_DigestVerify(mctx, final_sig, final_siglen,
                                        (const unsigned char *)message,
                                        msg_len)))
            goto err;
    }
    else
    {
        if (!TEST_true(SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(),
                                                   NULL, 0,
                                                   (const uint8_t *)message,
                                                   msg_len, digest, &dlen)) ||
            !TEST_true(SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen,
                                           &sigbuf, &siglen)) ||
            !TEST_true(SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen,
                                           &final_sig, &final_siglen)))
            goto err;

        if (!TEST_ptr(mctx = EVP_MD_CTX_new()) || !TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, complete_key1)) || !TEST_true(EVP_DigestVerify(mctx, final_sig, final_siglen, (const unsigned char *)message, msg_len)))
            goto err;
    }

    ret = 1;
err:
    ret ? printf("%s: success!\n", __func__) : printf("%s: error!\n", __func__);

    // EVP_PKEY_free(key1);
    // EVP_PKEY_free(key2);
    // EVP_PKEY_free(pubkey1);
    // EVP_PKEY_free(pubkey2);
    // EVP_PKEY_free(complete_key1);
    // EVP_PKEY_free(complete_key2);
    // EVP_PKEY_free(temp_key);
    // EVP_MD_CTX_free(mctx);
    // OPENSSL_free(sigbuf);
    return ret;
}


static int test_sm2_threshold_decrypt(void)
{
    int ret = 0;
    const char *msg = "hello sm2 threshold";
    int msg_len = strlen(msg);
    EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
    EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIGNUM *w = NULL;
    EC_POINT *T1 = NULL, *T2 = NULL;
    unsigned char *ct = NULL, *pt = NULL;
    size_t pt_len, outlen;

    if (!TEST_ptr(key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")) || !TEST_ptr(key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2")))
        goto err;

    if (!TEST_ptr(pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1)) || !TEST_ptr(pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2)))
        goto err;

    if (!TEST_ptr(complete_key1 =
                      SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2)) ||
        !TEST_ptr(complete_key2 =
                      SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1)))
        goto err;

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new(complete_key1, NULL)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt_init(pctx) == 1))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, NULL, &outlen,
                                    (const unsigned char *)msg, msg_len) == 1))
        goto err;

    if (!TEST_ptr(ct = OPENSSL_malloc(outlen)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, ct, &outlen,
                                    (const unsigned char *)msg, msg_len) == 1))
        goto err;

    if (!TEST_true(SM2_THRESHOLD_decrypt1(ct, outlen, &w, &T1)))
        goto err;

    if (!TEST_true(SM2_THRESHOLD_decrypt2(key2, T1, &T2)))
        goto err;

    if (!TEST_true(SM2_THRESHOLD_decrypt3(key1, ct, outlen, w, T2, &pt, &pt_len)))
        goto err;

    if (!TEST_int_eq(pt_len, msg_len))
        goto err;

    if (!TEST_strn_eq((const char *)pt, msg, msg_len))
        goto err;

    ret = 2;
err:
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(pubkey1);
    EVP_PKEY_free(pubkey2);
    EVP_PKEY_free(complete_key1);
    EVP_PKEY_free(complete_key2);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(ct);
    BN_free(w);
    EC_POINT_free(T1);
    EC_POINT_free(T2);
    OPENSSL_free(pt);

    return ret;
}

static int init()
{
    int ret = 0;
    const char *msg = "hello sm2 threshold";
    int msg_len = strlen(msg);
    // EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
    // EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    
    key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1);
    pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2);
    complete_key1 =
                      SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2);
    complete_key2 =
                      SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1);
    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new(complete_key1, NULL)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt_init(pctx) == 1))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, NULL, &outlen,
                                    (const unsigned char *)msg, msg_len) == 1))
        goto err;

    // if (!TEST_ptr(ct = OPENSSL_malloc(outlen)))
    //     goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, ct, &outlen,
                                    (const unsigned char *)msg, msg_len) == 1))
        goto err;

    for (size_t i = 0; i < 100; i++)
    {
        SM2_THRESHOLD_decrypt1(ct, outlen, &w, &T1);
        SM2_THRESHOLD_decrypt2(key2, T1, &T2);
        SM2_THRESHOLD_decrypt3(key1, ct, outlen, w, T2, &pt, &pt_len);
    }

    if (!TEST_int_eq(pt_len, msg_len))
        goto err;

    if (!TEST_strn_eq((const char *)pt, msg, msg_len))
        goto err;

    ret = 2;
err:
    ret ? printf("%s: success\n", __func__) : printf("%s: error\n", __func__);
    // EVP_PKEY_free(key1);
    // EVP_PKEY_free(key2);
    // EVP_PKEY_free(pubkey1);
    // EVP_PKEY_free(pubkey2);
    // EVP_PKEY_free(complete_key1);
    // EVP_PKEY_free(complete_key2);
    EVP_PKEY_CTX_free(pctx);
    // OPENSSL_free(ct);
    // BN_free(w);
    // EC_POINT_free(T1);
    // EC_POINT_free(T2);
    // OPENSSL_free(pt);

    return ret;
}

static int init_genkeys()
{
    int id = 0;
    // key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    // pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1);
    pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2);
    // complete_key1 = SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2);
    // complete_key2 = SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1);

//     /* Test SM2 threshold sign with id */
//     // 计算哈希值
//     SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(), NULL, 0, (const uint8_t *)message, msg_len, digest, &dlen);
//     // 完成哈希值第一部分计算
//     temp_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
//     SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen, &sigbuf, &siglen);
//     // 完成哈希值第二部分计算
//     SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen, &final_sig, &final_siglen);

//     if (!TEST_ptr(mctx = EVP_MD_CTX_new()) || !TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, complete_key1)) || !TEST_true(EVP_DigestVerify(mctx, final_sig, final_siglen, (const unsigned char *)message, msg_len)))
//         goto err;

//     ret = 1;
// err:
//     ret ? printf("%s: success!\n", __func__) : printf("%s: error!\n", __func__);
//     return ret;
}

static int init_cosign()
{
    int id = 0;
    key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1);
    pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2);
    complete_key1 = SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2);
    complete_key2 = SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1);

    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    for (size_t i = 0; i < MAX_SIZE; i++)
    {
        sigbuf_signtest[i] = NULL;
        final_sig_signtest[i] = NULL;
    }
    

    /* Test SM2 threshold sign with id */
    // 计算哈希值
    SM2_THRESHOLD_sign1_oneshot(complete_key1, EVP_sm3(), NULL, 0, (const uint8_t *)message, msg_len, digest, &dlen);

    for (size_t i = 0; i < 100; i++)
    {
        // 完成哈希值第一部分计算
        temp_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen, &sigbuf, &siglen);
        // 完成哈希值第二部分计算
        SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen, &final_sig, &final_siglen);
    }
    
    if (!TEST_ptr(mctx = EVP_MD_CTX_new()) || !TEST_true(EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, complete_key1)) || !TEST_true(EVP_DigestVerify(mctx, final_sig, final_siglen, (const unsigned char *)message, msg_len)))
        goto err;

    ret = 1;
err:
    ret ? printf("%s: success!\n", __func__) : printf("%s: error!\n", __func__);
    return ret;
}

void init_codec(){
        int ret = 0;
    const char *msg = "hello sm2 threshold";
    int msg_len = strlen(msg);
    // EVP_PKEY *key1 = NULL, *key2 = NULL, *pubkey1 = NULL, *pubkey2 = NULL;
    // EVP_PKEY *complete_key1 = NULL, *complete_key2 = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    
    key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    key2 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1);
    pubkey2 = SM2_THRESHOLD_derive_partial_pubkey(key2);
    complete_key1 =
                      SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2);
    complete_key2 =
                      SM2_THRESHOLD_derive_complete_pubkey(key2, pubkey1);
    if (!TEST_true(EVP_PKEY_eq(complete_key1, complete_key2)))
        goto err;

    // 加密
    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new(complete_key1, NULL)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt_init(pctx) == 1))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, NULL, &outlen,
                                    (const unsigned char *)msg, msg_len) == 1))
        goto err;
    
    printf("%s: init\n", __func__);

    if (!TEST_ptr(ct = OPENSSL_malloc(outlen)))
        goto err;

    if (!TEST_true(EVP_PKEY_encrypt(pctx, ct, &outlen,
                                    (const unsigned char *)msg, msg_len) == 1))
        goto err;

    // 循环解密
    for (size_t i = 0; i < 10; i++)
    {
        if (!TEST_true(SM2_THRESHOLD_decrypt1(ct, outlen, &w, &T1)))
            goto err;
        if (!TEST_true(SM2_THRESHOLD_decrypt2(key2, T1, &T2)))
            goto err;
        if (!TEST_true(SM2_THRESHOLD_decrypt3(key1, ct, outlen, w, T2, &pt, &pt_len)))
            goto err;
    }

    printf("%s: len cmp\n", __func__);
    printf("%s: %d\n", __func__, pt_len);
    printf("%s: %d\n", __func__, msg_len);

    if (!TEST_int_eq(pt_len, msg_len))
        goto err;
    printf("%s: len equal\n", __func__);
    if (!TEST_strn_eq((const char *)pt, msg, msg_len))
        goto err;

    ret = 2;
err:
    ret ? printf("%s: success\n", __func__) : printf("%s: error\n", __func__);
    // EVP_PKEY_free(key1);
    // EVP_PKEY_free(key2);
    // EVP_PKEY_free(pubkey1);
    // EVP_PKEY_free(pubkey2);
    // EVP_PKEY_free(complete_key1);
    // EVP_PKEY_free(complete_key2);
    EVP_PKEY_CTX_free(pctx);
    // OPENSSL_free(ct);
    // BN_free(w);
    // EC_POINT_free(T1);
    // EC_POINT_free(T2);
    // OPENSSL_free(pt);

    return ret;
}

#endif

void run_genkey(int pid, size_t start, size_t end)
{
    for(int i=start;i<end;i++){
        key1 = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        pubkey1 = SM2_THRESHOLD_derive_partial_pubkey(key1);
        complete_key1 = SM2_THRESHOLD_derive_complete_pubkey(key1, pubkey2);
    }
    exit(pid+100);
}

void run_cosign(int pid, size_t start, size_t end)
{
    for(int i=start;i<end;i++){
        // 完成哈希值第一部分计算
        temp_key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        SM2_THRESHOLD_sign2(key2, temp_key, digest, dlen, &(sigbuf_signtest[i]), &(siglen_signtest[i]));
        // 完成哈希值第二部分计算
        SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen, &(final_sig_signtest[i]), &(final_siglen_signtest[i]));
    }
    exit(pid+100);
}

void run_codec(int pid, size_t start, size_t end)
{
    for(int i=start;i<end;i++){
        SM2_THRESHOLD_decrypt1(ct, outlen, &w, &T1);
        SM2_THRESHOLD_decrypt2(key2, T1, &T2);
        SM2_THRESHOLD_decrypt3(key1, ct, outlen, w, T2, &pt, &pt_len);
    }
    exit(pid+100);
err:
    printf("%s: error\n", __func__);
    exit(pid+100);
}
int main(void)
{
    // ADD_TEST(test_sm2_threshold_keygen);
    // ADD_ALL_TESTS(test_sm2_threshold_sign, 2);
    // ADD_TEST(test_sm2_threshold_decrypt);
    // test_sm2_threshold_keygen();
    // test_sm2_threshold_sign(0);
    // test_sm2_threshold_sign(1);

#if 0
    // 多进程测试：密钥生成
    init_genkeys();
    bench_multiprocesses("SM2_co_gkey", 10000, 1, run_genkey);
    bench_multiprocesses("SM2_co_gkey", MAX_SIZE, 16, run_genkey);
    bench_multiprocesses("SM2_co_gkey", MAX_SIZE, 32, run_genkey);
    bench_multiprocesses("SM2_co_gkey", MAX_SIZE, 64, run_genkey);
#endif

#if 1
    // 多进程测试：协同签名
    init_cosign();
    bench_multiprocesses("SM2_co_sign", 10000, 16, run_cosign);
    bench_multiprocesses("SM2_co_sign", MAX_SIZE, 16, run_cosign);
    bench_multiprocesses("SM2_co_sign", MAX_SIZE, 32, run_cosign);
    bench_multiprocesses("SM2_co_sign", MAX_SIZE, 64, run_cosign);
#endif

#if 0
    // 多进程测试：协同解密
    init_codec();
    bench_multiprocesses("SM2_co_dec", 10000, 16, run_codec);
    bench_multiprocesses("SM2_co_dec", MAX_SIZE, 16, run_codec);
    bench_multiprocesses("SM2_co_dec", MAX_SIZE, 32, run_codec);
    bench_multiprocesses("SM2_co_dec", MAX_SIZE, 64, run_codec);
#endif
    // init();
    return 0;
}
