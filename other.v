module xecc

// https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#selections
const evp_pkey_key_parameters = C.EVP_PKEY_KEY_PARAMETERS
const evp_pkey_public_key = C.EVP_PKEY_PUBLIC_KEY
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR

// POINT_CONVERSION
const point_conversion_compressed = 2
const point_conversion_uncompressed = 4
const point_conversion_hybrid = 6
const openssl_ec_named_curve = C.OPENSSL_EC_NAMED_CURVE

// Taken from https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#examples
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

fn PrivateKey.from_bytes(bytes []u8) !PrivateKey {
	mut pkey := C.EVP_PKEY_new()

	priv := C.BN_bin2bn(bytes.data, bytes.len, 0)
	param_bld := C.OSSL_PARAM_BLD_new()
	n := C.OSSL_PARAM_BLD_push_utf8_string(param_bld, 'group'.str, sn_prime256v1.str,
		0)
	assert n == 1
	nn := C.OSSL_PARAM_BLD_push_utf8_string(param_bld, 'encoding'.str, 'named_curve'.str,
		0)
	assert nn == 1
	ff := C.OSSL_PARAM_BLD_push_utf8_string(param_bld, 'point-format'.str, 'uncompressed'.str,
		0)
	assert ff == 1
	m := C.OSSL_PARAM_BLD_push_BN(param_bld, 'priv'.str, priv)
	assert m == 1
	// o := C.OSSL_PARAM_BLD_push_octet_string(param_bld, 'pub'.str, pub_data.data, pub_data.len)
	// assert o == 1
	params := C.OSSL_PARAM_BLD_to_param(param_bld)

	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_ec, 0)
	assert pctx != 0
	qq := C.EVP_PKEY_paramgen_init(pctx)
	assert qq == 1
	mmm := C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid_prime256v1)
	assert mmm > 0

	pp := C.EVP_PKEY_keygen_init(pctx)
	assert pp == 1

	p := C.EVP_PKEY_fromdata_init(pctx)
	assert p == 1
	q := C.EVP_PKEY_fromdata(pctx, &pkey, evp_pkey_keypair, params)
	assert q == 1

	// TODO: right way to check the key, its fails on every check methods.
	pvkey := PrivateKey{
		key: pkey
	}

	// TODO: cleansup
	return pvkey
}

fn (pb PublicKey) dump_key() string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_public(bo, pb.key, 2, 0)
	assert n == 1
	size := 0
	mut m := C.BIO_read_ex(bo, 0, 1024, &size)

	mut buf := []u8{len: size}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	assert m == 1

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}

fn (pv PrivateKey) dump_params() string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_params(bo, pv.key, 2, 0)
	assert n == 1
	size := 0
	mut m := C.BIO_read_ex(bo, 0, 1024, &size)

	mut buf := []u8{len: size}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	assert m == 1

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}

fn (pv PrivateKey) dump_key() string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_private(bo, pv.key, 2, 0)
	assert n == 1
	size := 0
	mut m := C.BIO_read_ex(bo, 0, 1024, &size)

	mut buf := []u8{len: size}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	assert m == 1

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}

fn (pv PrivateKey) bytes() ![]u8 {
	bn := C.BN_new()
	n := C.EVP_PKEY_get_bn_param(pv.key, 'priv'.str, &bn)
	if n != 1 {
		return error('Null private key')
	}
	num_bytes := C.BN_num_bytes(bn)
	mut privkey := []u8{len: int(num_bytes)}
	m := C.BN_bn2bin(bn, privkey.data)
	assert m != 0
	C.BN_free(bn)
	return privkey
}

fn (pv PrivateKey) info() {
	bn := C.BN_new()
	n := C.EVP_PKEY_get_bn_param(pv.key, 'priv'.str, &bn)
	assert n == 1
	num_bytes := C.BN_num_bytes(bn)
	mut privkey := []u8{len: int(num_bytes)}
	m := C.BN_bn2bin(bn, privkey.data)
	assert m != 0
	dump(privkey.hex())
	dump(privkey.len)

	size := 0
	mut g := C.EVP_PKEY_get_octet_string_param(pv.key, 'pub'.str, 0, 100, &size)
	mut pubkey := []u8{len: size}

	g = C.EVP_PKEY_get_octet_string_param(pv.key, 'pub'.str, pubkey.data, pubkey.len,
		&size)
	assert g == 1
	dump(pubkey[..size].hex())
	dump(pubkey[..size].len)
}

fn (pb PublicKey) info() {
	bn := C.BN_new()
	n := C.EVP_PKEY_get_bn_param(pb.key, 'priv'.str, &bn)
	assert n == 0 // should not present
	num_bytes := C.BN_num_bytes(bn)
	mut buf := []u8{len: int(num_bytes)}
	m := C.BN_bn2bin(bn, buf.data)
	assert m == 0
	assert buf.hex() == ''
	assert buf.len == 0

	size := 0
	mut g := C.EVP_PKEY_get_octet_string_param(pb.key, 'pub'.str, 0, 800, &size)
	mut pubkey := []u8{len: size}

	g = C.EVP_PKEY_get_octet_string_param(pb.key, 'pub'.str, pubkey.data, pubkey.len,
		&size)
	assert g == 1

	dump(pubkey[..size].hex())
	dump(pubkey.len)
}
