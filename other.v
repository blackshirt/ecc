module xecc

#include <openssl/param_build.h>

// # define EVP_PKEY_KEY_PARAMETERS \ ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )
// # define EVP_PKEY_PRIVATE_KEY    \ ( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
// # define EVP_PKEY_PUBLIC_KEY     \ ( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
// # define EVP_PKEY_KEYPAIR        \ ( EVP_PKEY_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )

const evp_pkey_key_parameters = C.EVP_PKEY_KEY_PARAMETERS
const evp_pkey_private_key = C.EVP_PKEY_PRIVATE_KEY
const evp_pkey_public_key = C.EVP_PKEY_PUBLIC_KEY
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR

// POINT_CONVERSION
const point_conversion_compressed = 2
const point_conversion_uncompressed = 4
const point_conversion_hybrid = 6

// Taken from https://man.netbsd.org/EVP_PKEY_fromdata.3
// Fixed data to represent the private and public key.
const priv_data = [u8(0xb9), 0x2f, 0x3c, 0xe6, 0x2f, 0xfb, 0x45, 0x68, 0x39, 0x96, 0xf0, 0x2a,
	0xaf, 0x6c, 0xda, 0xf2, 0x89, 0x8a, 0x27, 0xbf, 0x39, 0x9b, 0x7e, 0x54, 0x21, 0xc2, 0xa1, 0xe5,
	0x36, 0x12, 0x48, 0x5d]

// UNCOMPRESSED FORMAT */
const pub_data = [u8(point_conversion_uncompressed), 0xcf, 0x20, 0xfb, 0x9a, 0x1d, 0x11, 0x6c,
	0x5e, 0x9f, 0xec, 0x38, 0x87, 0x6c, 0x1d, 0x2f, 0x58, 0x47, 0xab, 0xa3, 0x9b, 0x79, 0x23, 0xe6,
	0xeb, 0x94, 0x6f, 0x97, 0xdb, 0xa3, 0x7d, 0xbd, 0xe5, 0x26, 0xca, 0x07, 0x17, 0x8d, 0x26, 0x75,
	0xff, 0xcb, 0x8e, 0xb6, 0x84, 0xd0, 0x24, 0x02, 0x25, 0x8f, 0xb9, 0x33, 0x6e, 0xcf, 0x12, 0x16,
	0x2f, 0x5c, 0xcd, 0x86, 0x71, 0xa8, 0xbf, 0x1a, 0x47]

fn C.BN_bin2bn(s &u8, len int, ret &C.BIGNUM) &C.BIGNUM

// OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
fn C.OSSL_PARAM_BLD_new() &C.OSSL_PARAM_BLD

// int OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *bld, const char *key, const char *buf, size_t bsize);
fn C.OSSL_PARAM_BLD_push_utf8_string(bld &C.OSSL_PARAM_BLD, key &u8, buf &u8, bsize int) int

// int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn);
fn C.OSSL_PARAM_BLD_push_BN(bld &C.OSSL_PARAM_BLD, key &u8, bn &C.BIGNUM) int

// int OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *bld, const char *key, const void *buf, size_t bsize);
fn C.OSSL_PARAM_BLD_push_octet_string(bld &C.OSSL_PARAM_BLD, key &u8, buf voidptr, bsize int) int

// OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld);
fn C.OSSL_PARAM_BLD_to_param(bld &C.OSSL_PARAM_BLD) &C.OSSL_PARAM

// int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
fn C.EVP_PKEY_fromdata_init(ctx &C.EVP_PKEY_CTX) int

// int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[]);
fn C.EVP_PKEY_fromdata(ctx &C.EVP_PKEY_CTX, ppkey &&C.EVP_PKEY, selection int, params &C.OSSL_PARAM) int

@[typedef]
struct C.OSSL_PARAM_BLD {}

@[typedef]
struct C.OSSL_PARAM {}

@[typedef]
struct C.BIGNUM {}

fn load_key_from_bytes() !&C.EVP_PKEY {
	mut pkey := C.EVP_PKEY_new()

	priv := C.BN_bin2bn(priv_data.data, priv_data.len, 0)
	param_bld := C.OSSL_PARAM_BLD_new()
	n := C.OSSL_PARAM_BLD_push_utf8_string(param_bld, 'group'.str, sn_prime256v1.str,
		0)
	dump(n)
	m := C.OSSL_PARAM_BLD_push_BN(param_bld, 'priv'.str, priv)
	dump(m)
	o := C.OSSL_PARAM_BLD_push_octet_string(param_bld, 'pub'.str, pub_data.data, pub_data.len)
	dump(o)
	params := C.OSSL_PARAM_BLD_to_param(param_bld)

	ctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_ec, 0)
	p := C.EVP_PKEY_fromdata_init(ctx)
	dump(p)
	q := C.EVP_PKEY_fromdata(ctx, &pkey, evp_pkey_keypair, params)
	dump(q)
	// TODO: cleansup
	return pkey
}
