module xecc

// https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#selections
const evp_pkey_key_parameters = C.EVP_PKEY_KEY_PARAMETERS
const evp_pkey_public_key = C.EVP_PKEY_PUBLIC_KEY
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR

// POINT_CONVERSION FORAMT
const point_conversion_compressed = 2
const point_conversion_uncompressed = 4
const point_conversion_hybrid = 6
// flag
const openssl_ec_named_curve = C.OPENSSL_EC_NAMED_CURVE

fn PrivateKey.from_bytes(bytes []u8, opt CurveOptions) !PrivateKey {
	if bytes.len != opt.nid.size() {
		return error('bytes length does not match with curve provided')
	}
	mut pkey := C.EVP_PKEY_new()
	if pkey == 0 {
		C.EVP_PKEY_free(pkey)
		return error('EVP_PKEY_new failed')
	}
	// convert bytes to bignum
	priv := C.BN_bin2bn(bytes.data, bytes.len, 0)
	if priv == 0 {
		C.BN_free(priv)
		C.EVP_PKEY_free(pkey)
		return error('BN_bin2bn failed from bytes')
	}
	// build public key bytes
	group := C.EC_GROUP_new_by_curve_name(opt.nid.to_int())
	if group == 0 {
		C.EC_GROUP_free(group)
		C.BN_free(priv)
		C.EVP_PKEY_free(pkey)
		return error('EC_GROUP_new_by_curve_name failed')
	}
	point := ec_point_mult(group, priv)!
	pub_bytes := point_2_buf(group, point, point_conversion_uncompressed)!

	param_bld := C.OSSL_PARAM_BLD_new()
	n := C.OSSL_PARAM_BLD_push_utf8_string(param_bld, voidptr('group'.str), voidptr(opt.nid.str().str),
		0)
	assert n == 1

	m := C.OSSL_PARAM_BLD_push_BN(param_bld, voidptr('priv'.str), priv)
	assert m == 1

	o := C.OSSL_PARAM_BLD_push_octet_string(param_bld, voidptr('pub'.str), pub_bytes.data,
		pub_bytes.len)
	assert o == 1
	// build params
	params := C.OSSL_PARAM_BLD_to_param(param_bld)

	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_ec, 0)
	assert pctx != 0

	p := C.EVP_PKEY_fromdata_init(pctx)
	assert p == 1
	q := C.EVP_PKEY_fromdata(pctx, &pkey, evp_pkey_keypair, params)
	assert q == 1

	// TODO: right way to check the key, its fails on check methods.

	pvkey := PrivateKey{
		key: pkey
	}
	// Cleans up
	C.EC_POINT_free(point)
	C.BN_free(priv)
	C.EC_GROUP_free(group)
	C.OSSL_PARAM_BLD_free(param_bld)
	C.OSSL_PARAM_free(params)
	C.EVP_PKEY_CTX_free(pctx)

	return pvkey
}

fn (pv PrivateKey) params() string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_params(bo, pv.key, 2, 0)
	assert n == 1
	size := usize(0)
	mut m := C.BIO_read_ex(bo, 0, default_bioread_bufsize, &size)

	mut buf := []u8{len: int(size)}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	assert m == 1

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}

// dump_key represents PrivateKey in human readable string.
pub fn (pv PrivateKey) dump_key() !string {
	bo := C.BIO_new(C.BIO_s_mem())
	if bo == 0 {
		C.BIO_free_all(bo)
		return error('BIO_new failed')
	}
	n := C.EVP_PKEY_print_private(bo, pv.key, 2, 0)
	assert n == 1
	if n != 1 {
		C.BIO_free_all(bo)
		return error('print private failed')
	}
	size := usize(0)
	mut m := C.BIO_read_ex(bo, 0, default_bioread_bufsize, &size)

	mut buf := []u8{len: int(size)}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	assert m == 1
	if m != 1 {
		C.BIO_free_all(bo)
		return error('bio read ex failed')
	}

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}

// bytes gets underlying private key bytes
pub fn (pv PrivateKey) bytes() ![]u8 {
	bn := C.BN_new()
	n := C.EVP_PKEY_get_bn_param(pv.key, voidptr('priv'.str), &bn)
	if n != 1 {
		C.BN_free(bn)
		return []u8{}
	}
	// padded to curve key size
	cs := C.EVP_PKEY_get_bits(pv.key)
	padded := (cs + 7) / 8

	mut privkey := []u8{len: int(padded)}
	m := C.BN_bn2binpad(bn, privkey.data, padded)
	assert m != 0
	C.BN_free(bn)
	return privkey
}

// bytes gets bytes of encoded public key bytes
pub fn (pb PublicKey) bytes() ![]u8 {
	size := usize(C.EVP_PKEY_get_size(pb.key))
	mut buf := []u8{len: int(size)}
	mut g := C.EVP_PKEY_get_octet_string_param(pb.key, voidptr('encoded-pub-key'.str),
		buf.data, buf.len, &size)
	assert g == 1

	pbk_bytes := buf[..size].clone()
	unsafe { buf.free() }
	return pbk_bytes
}

// constant of buffer size for bio read
const default_bioread_bufsize = 1024

// dump_key represents public key in human readable string.
pub fn (pb PublicKey) dump_key() !string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_public(bo, pb.key, 2, 0)
	assert n == 1
	size := usize(0)
	mut m := C.BIO_read_ex(bo, 0, default_bioread_bufsize, &size)

	mut buf := []u8{len: int(size)}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	assert m == 1

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}
