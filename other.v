module xecc

#include <openssl/param_build.h>
#include <openssl/types.h>
#include <openssl/bio.h>
#include <openssl/core.h>
#include <stdio.h>

// # define EVP_PKEY_KEY_PARAMETERS \ ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )
// # define EVP_PKEY_PRIVATE_KEY    \ ( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )
// # define EVP_PKEY_PUBLIC_KEY     \ ( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY )
// # define EVP_PKEY_KEYPAIR        \ ( EVP_PKEY_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )

const evp_pkey_key_parameters = C.EVP_PKEY_KEY_PARAMETERS
const evp_pkey_private_key = C.EVP_PKEY_PRIVATE_KEY
const evp_pkey_public_key = C.EVP_PKEY_PUBLIC_KEY
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR
const pkey_param_priv_key = C.OSSL_PKEY_PARAM_PRIV_KEY
// POINT_CONVERSION
const point_conversion_compressed = 2
const point_conversion_uncompressed = 4
const point_conversion_hybrid = 6
const openssl_ec_named_curve = C.OPENSSL_EC_NAMED_CURVE

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

@[typedef]
struct C.ASN1_PCTX {}

fn load_privkey_from_bytes() !&C.EVP_PKEY {
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

	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_ec, 0)
	p := C.EVP_PKEY_fromdata_init(pctx)
	dump(p)
	_ := C.EVP_PKEY_CTX_set_ec_param_enc(pctx, openssl_ec_named_curve)
	q := C.EVP_PKEY_fromdata(pctx, &pkey, evp_pkey_keypair, params)
	dump(q)

	nck := C.EVP_PKEY_check(pctx)

	// TODO: cleansup
	return pkey
}

// int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
fn C.EVP_PKEY_print_public(out &C.BIO, pkey &C.EVP_PKEY, indent int, pctx &C.ASN1_PCTX) int

// int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
fn C.EVP_PKEY_print_private(out &C.BIO, pkey &C.EVP_PKEY, indent int, pctx &C.ASN1_PCTX) int

// int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx);
fn C.EVP_PKEY_print_params(out &C.BIO, pkey &C.EVP_PKEY, indent int, pctx &C.ASN1_PCTX) int
fn C.BIO_read(b &C.BIO, buf voidptr, len int) int
fn C.BIO_gets(b &C.BIO, buf &u8, size int) int
fn C.BN_new() &C.BIGNUM
fn C.BN_free(a &C.BIGNUM)
fn C.BIO_new_fp(stream &C.FILE, flags int) &C.BIO
fn C.BIO_flush(b &C.BIO) int

// int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
fn C.BIO_read_ex(b &C.BIO, data voidptr, dlen int, readbytes &int) int

@[typedef]
struct C.FILE {}

const stdout = C.stdout
const bio_noclose = C.BIO_NOCLOSE

fn (pb PublicKey) dump_key() string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_private(bo, pb.key, 2, 0)
	size := 0
	_ := C.BIO_read_ex(bo, 0, 1024, &size)
	dump(size)
	mut buf := []u8{len: size}
	_ := C.BIO_read_ex(bo, buf.data, buf.len, &size)
	dump(size)
	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)
	return output.bytestr()
}

fn (pv PrivateKey) dump_params() string {
	bo := C.BIO_new(C.BIO_s_mem())
	_ := C.EVP_PKEY_print_params(bo, pv.key, 2, 0)
	size := 0
	_ := C.BIO_read_ex(bo, 0, 1024, &size)
	dump(size)
	mut buf := []u8{len: size}
	_ := C.BIO_read_ex(bo, buf.data, buf.len, &size)
	dump(size)
	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)
	return output.bytestr()
}

fn (pv PrivateKey) dump_key() string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_private(bo, pv.key, 2, 0)
	size := 0
	_ := C.BIO_read_ex(bo, 0, 1024, &size)
	dump(size)
	mut buf := []u8{len: size}
	_ := C.BIO_read_ex(bo, buf.data, buf.len, &size)
	dump(size)
	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)
	return output.bytestr()
}

fn (pv PrivateKey) info() {
	bn := C.BN_new()
	n := C.EVP_PKEY_get_bn_param(pv.key, 'priv'.str, &bn)
	num_bytes := C.BN_num_bytes(bn)
	mut buf := []u8{len: int(num_bytes)}
	m := C.BN_bn2bin(bn, buf.data)
	dump(m)
	dump(buf.hex())
	dump(priv_data.hex())
	dump(buf.hex() == priv_data.hex())
	dump(buf.len)

	size := 0
	g := C.EVP_PKEY_get_octet_string_param(pv.key, 'pub'.str, 0, 100, &size)
	mut buf2 := []u8{len: size}
	dump(size)
	h := C.EVP_PKEY_get_octet_string_param(pv.key, 'pub'.str, buf2.data, buf2.len, &size)
	dump(buf2.hex())
	dump(buf2.len)
}

fn (pb PublicKey) info() {
	bn := C.BN_new()
	n := C.EVP_PKEY_get_bn_param(pb.key, 'priv'.str, &bn)
	num_bytes := C.BN_num_bytes(bn)
	mut buf := []u8{len: int(num_bytes)}
	m := C.BN_bn2bin(bn, buf.data)
	dump(m)
	dump(buf.hex())
	dump(buf.len)

	size := 0
	g := C.EVP_PKEY_get_octet_string_param(pb.key, 'pub'.str, 0, 800, &size)
	mut buf2 := []u8{len: size}
	dump(size)
	h := C.EVP_PKEY_get_octet_string_param(pb.key, 'pub'.str, buf2.data, buf2.len, &size)
	dump(buf2.hex())
	dump(buf2.len)
}

fn C.BN_bn2bin(a &C.BIGNUM, to &u8) int
fn C.BN_num_bytes(a &C.BIGNUM) int

// int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name, BIGNUM **bn);
fn C.EVP_PKEY_get_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &&C.BIGNUM) int
// int C.EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name, const BIGNUM *bn);
fn C.EVP_PKEY_set_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &C.BIGNUM) int 
// int EVP_PKEY_get_utf8_string_param(const EVP_PKEY *pkey, const char *key_name, char *str, size_t max_buf_sz, size_t *out_len);
fn C.EVP_PKEY_get_utf8_string_param(pkey &C.EVP_PKEY, key_name &u8, st &u8, max_buf_sz int, outlen &int) int

// int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name, unsigned char *buf, size_t max_buf_sz, size_t *out_len);
fn C.EVP_PKEY_get_octet_string_param(pkey &C.EVP_PKEY, key_name &u8, buf &u8, max_buf_sz int, out_len &int) int
// int EVP_PKEY_set_octet_string_param(EVP_PKEY *pkey, const char *key_name, const unsigned char *buf, size_t bsize);
fn C.EVP_PKEY_set_octet_string_param(pkey &C.EVP_PKEY, key_name &u8, buf &u8, bsize int) int 

fn (pv PrivateKey) copy_params() !PrivateKey {
	tokey := C.EVP_PKEY_new()
	n := C.EVP_PKEY_copy_parameters(tokey, pv.key)
	return PrivateKey{
		key: tokey
	}
}
