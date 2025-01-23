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

@[typedef]
struct C.EC_GROUP {}

// int EVP_PKEY_get_base_id(const EVP_PKEY *pkey);
fn C.EVP_PKEY_base_id(key &C.EVP_PKEY) int
fn C.EVP_PKEY_keygen_init(ctx &C.EVP_PKEY_CTX) int // 1 success
fn C.EVP_PKEY_keygen(ctx &C.EVP_PKEY_CTX, key &&C.EVP_PKEY) int
fn C.EVP_PKEY_new() &C.EVP_PKEY
fn C.EVP_PKEY_free(key &C.EVP_PKEY)
fn C.EVP_PKEY_dup(key &C.EVP_PKEY) &C.EVP_PKEY
fn C.EVP_EC_gen(curve voidptr) &C.EVP_PKEY

// int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name, const BIGNUM *bn);
fn C.EVP_PKEY_set_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &C.BIGNUM) int

// int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey, const unsigned char *pub, size_t publen);
fn C.EVP_PKEY_set1_encoded_public_key(pkey &C.EVP_PKEY, pub_data &u8, publen int) int

// size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub);
fn C.EVP_PKEY_get1_encoded_public_key(pkey &C.EVP_PKEY, ppub &&u8) int

// EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
fn C.EVP_PKEY_CTX_new_id(id int, e voidptr) &C.EVP_PKEY_CTX

// EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
fn C.EVP_PKEY_CTX_new(pkey &C.EVP_PKEY, e voidptr) &C.EVP_PKEY_CTX
fn C.EVP_PKEY_CTX_free(ctx &C.EVP_PKEY_CTX)

// int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid); 1 success
fn C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx &C.EVP_PKEY_CTX, nid int) int

// int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc);
fn C.EVP_PKEY_CTX_set_ec_param_enc(ctx &C.EVP_PKEY_CTX, prm int) int

// EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey, const char *propquery);
fn C.EVP_PKEY_CTX_new_from_pkey(libctx voidptr, pkey &C.EVP_PKEY, pq voidptr) &C.EVP_PKEY_CTX

// int EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
fn C.EVP_PKEY_verify_init(ctx &C.EVP_PKEY_CTX) int

// int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,const unsigned char *sig, size_t siglen,const unsigned char *tbs, size_t tbslen);
fn C.EVP_PKEY_verify(ctx &C.EVP_PKEY_CTX, sig &u8, siglen int, tbs &u8, tbslen int) int

// int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b);
fn C.EVP_PKEY_eq(a &C.EVP_PKEY, b &C.EVP_PKEY) int

// int EVP_PKEY_check(EVP_PKEY_CTX *ctx);
fn C.EVP_PKEY_check(ctx &C.EVP_PKEY_CTX) int

// EVP_PKEY_sign() does not hash the data to be signed, and therefore is normally used to sign digests
// int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);
fn C.EVP_PKEY_sign(ctx &C.EVP_PKEY_CTX, sig &u8, siglen &usize, tbs &u8, tbslen int) int

// int EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
fn C.EVP_PKEY_sign_init(ctx &C.EVP_PKEY_CTX) int

// int EVP_PKEY_get_bits(const EVP_PKEY *pkey);
fn C.EVP_PKEY_get_bits(pkey &C.EVP_PKEY) int

// int EVP_PKEY_get_size(const EVP_PKEY *pkey);
fn C.EVP_PKEY_get_size(pkey &C.EVP_PKEY) int

// int EVP_PKEY_get_security_bits(const EVP_PKEY *pkey);
fn C.EVP_PKEY_get_security_bits(pkey &C.EVP_PKEY) int

// const char *EVP_PKEY_get0_type_name(const EVP_PKEY *key);
fn C.EVP_PKEY_get0_type_name(key &C.EVP_PKEY) &char

// const char *EVP_PKEY_get0_description(const EVP_PKEY *key);
fn C.EVP_PKEY_get0_description(key &C.EVP_PKEY) &char

// get actual NID
// int EVP_PKEY_get_id(const EVP_PKEY *pkey);
fn C.EVP_PKEY_get_id(pkey &C.EVP_PKEY) int

// #define NID_X9_62_prime_field           406
// int EVP_PKEY_get_ec_point_conv_form(const EVP_PKEY *pkey);
fn C.EVP_PKEY_get_ec_point_conv_form(pkey &C.EVP_PKEY) int

// int EVP_PKEY_get_group_name(EVP_PKEY *pkey, char *gname, size_t gname_sz, size_t *gname_len);
fn C.EVP_PKEY_get_group_name(pkey &C.EVP_PKEY, gname &u8, gname_sz u32, gname_len &usize) int
fn C.EVP_PKEY_get0_EC_KEY(pkey &C.EVP_PKEY) &C.EC_KEY

// int EVP_PKEY_public_check(EVP_PKEY_CTX *ctx);
fn C.EVP_PKEY_public_check(pctx &C.EVP_PKEY_CTX) int

// int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
fn C.EVP_PKEY_copy_parameters(to &C.EVP_PKEY, from &C.EVP_PKEY) int

// int EC_GROUP_get_curve_name(const EC_GROUP *group);
fn C.EC_GROUP_get_curve_name(g &C.EC_GROUP) int
fn C.EC_GROUP_free(group &C.EC_GROUP)
fn C.EC_GROUP_get_degree(g &C.EC_GROUP) int
fn C.EC_GROUP_get_curve_name(g &C.EC_GROUP) int

fn C.BIO_free_all(a &C.BIO)
fn C.EC_KEY_get0_group(key &C.EC_KEY) &C.EC_GROUP
