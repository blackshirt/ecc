module xecc

// Contains the core wrappers of OpenSLL crypto API
//
#flag darwin -L /opt/homebrew/opt/openssl/lib -I /opt/homebrew/opt/openssl/include

#flag -I/usr/include/openssl
#flag -lcrypto
#flag darwin -I/usr/local/opt/openssl/include
#flag darwin -L/usr/local/opt/openssl/lib
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/core.h>

@[typedef]
struct C.EVP_PKEY {}

fn C.EVP_PKEY_new() &C.EVP_PKEY
fn C.EVP_PKEY_free(key &C.EVP_PKEY)
fn C.EVP_PKEY_dup(key &C.EVP_PKEY) &C.EVP_PKEY
fn C.EVP_PKEY_base_id(key &C.EVP_PKEY) int
fn C.EVP_PKEY_keygen_init(ctx &C.EVP_PKEY_CTX) int // 1 success
fn C.EVP_PKEY_keygen(ctx &C.EVP_PKEY_CTX, key &&C.EVP_PKEY) int
fn C.EVP_EC_gen(curve voidptr) &C.EVP_PKEY
fn C.EVP_PKEY_set_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &C.BIGNUM) int
fn C.EVP_PKEY_set1_encoded_public_key(pkey &C.EVP_PKEY, pub_data &u8, publen int) int
fn C.EVP_PKEY_get1_encoded_public_key(pkey &C.EVP_PKEY, ppub &&u8) int
fn C.EVP_PKEY_verify_init(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_verify(ctx &C.EVP_PKEY_CTX, sig &u8, siglen int, tbs &u8, tbslen int) int
fn C.EVP_PKEY_eq(a &C.EVP_PKEY, b &C.EVP_PKEY) int
fn C.EVP_PKEY_check(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_sign(ctx &C.EVP_PKEY_CTX, sig &u8, siglen &usize, tbs &u8, tbslen int) int
fn C.EVP_PKEY_sign_init(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_get_bits(pkey &C.EVP_PKEY) int
fn C.EVP_PKEY_get_size(pkey &C.EVP_PKEY) int
fn C.EVP_PKEY_get_security_bits(pkey &C.EVP_PKEY) int
fn C.EVP_PKEY_get0_type_name(key &C.EVP_PKEY) &char
fn C.EVP_PKEY_get0_description(key &C.EVP_PKEY) &char
fn C.EVP_PKEY_get_id(pkey &C.EVP_PKEY) int
fn C.EVP_PKEY_get_ec_point_conv_form(pkey &C.EVP_PKEY) int
fn C.EVP_PKEY_get_group_name(pkey &C.EVP_PKEY, gname &u8, gname_sz u32, gname_len &usize) int
fn C.EVP_PKEY_get0_EC_KEY(pkey &C.EVP_PKEY) &C.EC_KEY
fn C.EVP_PKEY_public_check(pctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_copy_parameters(to &C.EVP_PKEY, from &C.EVP_PKEY) int
fn C.EVP_PKEY_paramgen_init(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_keygen_init(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_param_check_quick(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_private_check(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_print_public(out &C.BIO, pkey &C.EVP_PKEY, indent int, pctx voidptr) int
fn C.EVP_PKEY_print_private(out &C.BIO, pkey &C.EVP_PKEY, indent int, pctx voidptr) int
fn C.EVP_PKEY_print_params(out &C.BIO, pkey &C.EVP_PKEY, indent int, pctx voidptr) int
fn C.EVP_PKEY_get_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &&C.BIGNUM) int
fn C.EVP_PKEY_set_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &C.BIGNUM) int
fn C.EVP_PKEY_get_utf8_string_param(pkey &C.EVP_PKEY, key_name &u8, st &u8, max_buf_sz int, outlen &int) int
fn C.EVP_PKEY_get_octet_string_param(pkey &C.EVP_PKEY, key_name &u8, buf &u8, max_buf_sz int, out_len &int) int
fn C.EVP_PKEY_set_octet_string_param(pkey &C.EVP_PKEY, key_name &u8, buf &u8, bsize int) int
fn C.EVP_PKEY_fromdata_init(ctx &C.EVP_PKEY_CTX) int
fn C.EVP_PKEY_fromdata(ctx &C.EVP_PKEY_CTX, ppkey &&C.EVP_PKEY, selection int, params &C.OSSL_PARAM) int

fn C.i2d_PUBKEY_bio(bo &C.BIO, pkey &C.EVP_PKEY) int
fn C.d2i_PUBKEY_bio(bo &C.BIO, key &&C.EVP_PKEY) &C.EVP_PKEY

@[typedef]
struct C.EVP_PKEY_CTX {}

fn C.EVP_PKEY_CTX_new_id(id int, e voidptr) &C.EVP_PKEY_CTX
fn C.EVP_PKEY_CTX_new(pkey &C.EVP_PKEY, e voidptr) &C.EVP_PKEY_CTX
fn C.EVP_PKEY_CTX_free(ctx &C.EVP_PKEY_CTX)
fn C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx &C.EVP_PKEY_CTX, nid int) int // 1 success
fn C.EVP_PKEY_CTX_set_ec_param_enc(ctx &C.EVP_PKEY_CTX, prm int) int
fn C.EVP_PKEY_CTX_new_from_pkey(libctx voidptr, pkey &C.EVP_PKEY, pq voidptr) &C.EVP_PKEY_CTX

fn C.BIO_read(b &C.BIO, buf voidptr, len int) int
fn C.BIO_gets(b &C.BIO, buf &u8, size int) int
fn C.BIO_read_ex(b &C.BIO, data voidptr, dlen int, readbytes &int) int
fn C.BIO_flush(b &C.BIO) int
fn C.BIO_free_all(a &C.BIO)

@[typedef]
struct C.BIGNUM {}

fn C.BN_new() &C.BIGNUM
fn C.BN_free(a &C.BIGNUM)
fn C.BN_bn2bin(a &C.BIGNUM, to &u8) int
fn C.BN_bn2binpad(a &C.BIGNUM, to &u8, tolen int) int
fn C.BN_num_bytes(a &C.BIGNUM) int
fn C.BN_bin2bn(s &u8, len int, ret &C.BIGNUM) &C.BIGNUM

@[typedef]
struct C.OSSL_PARAM {}

@[typedef]
struct C.OSSL_PARAM_BLD {}

fn C.OSSL_PARAM_free(params &C.OSSL_PARAM)
fn C.OSSL_PARAM_BLD_free(param_bld &C.OSSL_PARAM_BLD)
fn C.OSSL_PARAM_BLD_new() &C.OSSL_PARAM_BLD
fn C.OSSL_PARAM_BLD_push_utf8_string(bld &C.OSSL_PARAM_BLD, key &u8, buf &u8, bsize int) int
fn C.OSSL_PARAM_BLD_push_BN(bld &C.OSSL_PARAM_BLD, key &u8, bn &C.BIGNUM) int
fn C.OSSL_PARAM_BLD_push_octet_string(bld &C.OSSL_PARAM_BLD, key &u8, buf voidptr, bsize int) int
fn C.OSSL_PARAM_BLD_to_param(bld &C.OSSL_PARAM_BLD) &C.OSSL_PARAM

@[typedef]
struct C.EC_GROUP {}

fn C.EC_GROUP_get_curve_name(g &C.EC_GROUP) int
fn C.EC_GROUP_free(group &C.EC_GROUP)
fn C.EC_GROUP_get_degree(g &C.EC_GROUP) int
fn C.EC_GROUP_get_curve_name(g &C.EC_GROUP) int

@[typedef]
struct C.EC_KEY {}

fn C.EC_KEY_get0_group(key &C.EC_KEY) &C.EC_GROUP

// Wrapper of digest and signing related of the C opaque and functions.

@[typedef]
struct C.EVP_MD {}

fn C.EVP_MD_free(md &C.EVP_MD)
fn C.EVP_sha256() &C.EVP_MD
fn C.EVP_sha384() &C.EVP_MD
fn C.EVP_sha512() &C.EVP_MD
fn C.EVP_sha3_256() &C.EVP_MD
fn C.EVP_sha3_384() &C.EVP_MD
fn C.EVP_sha3_512() &C.EVP_MD
fn C.EVP_shake128() &C.EVP_MD
fn C.EVP_shake256() &C.EVP_MD

@[typedef]
struct C.EVP_MD_CTX {}

fn C.EVP_MD_CTX_new() &C.EVP_MD_CTX
fn C.EVP_MD_CTX_free(ctx &C.EVP_MD_CTX)
fn C.EVP_MD_CTX_set_pkey_ctx(ctx &C.EVP_MD_CTX, pctx &C.EVP_PKEY_CTX)

// Non pre-hash digest routine
fn C.EVP_DigestSign(ctx &C.EVP_MD_CTX, sig &u8, siglen &usize, tbs &u8, tbslen int) int
fn C.EVP_DigestVerify(ctx &C.EVP_MD_CTX, sig &u8, siglen int, tbs &u8, tbslen int) int

// Recommended hashed signer routine
fn C.EVP_DigestSignInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, tipe &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) int
fn C.EVP_DigestSignUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt int) int
fn C.EVP_DigestSignFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen &usize) int
fn C.EVP_DigestVerifyInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, tipe &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) int
fn C.EVP_DigestVerifyUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt int) int
fn C.EVP_DigestVerifyFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen int) int
