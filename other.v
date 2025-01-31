module ecc

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

// from_bytes creates PrivateKey from provided bytes and options. The bytes length
// should match with underlying curve key size intended to be created in options.
pub fn PrivateKey.from_bytes(bytes []u8, opt CurveOptions) !PrivateKey {
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
	assert param_bld != 0

	n := C.OSSL_PARAM_BLD_push_utf8_string(param_bld, voidptr('group'.str), voidptr(opt.nid.str().str),
		0)
	m := C.OSSL_PARAM_BLD_push_BN(param_bld, voidptr('priv'.str), priv)
	o := C.OSSL_PARAM_BLD_push_octet_string(param_bld, voidptr('pub'.str), pub_bytes.data,
		pub_bytes.len)
	if n <= 0 || m <= 0 || o <= 0 {
		C.EC_POINT_free(point)
		C.BN_free(priv)
		C.EC_GROUP_free(group)
		C.OSSL_PARAM_BLD_free(param_bld)
		C.EVP_PKEY_free(pkey)
		return error('OSSL_PARAM_BLD_push FAILED')
	}

	// build params
	params := C.OSSL_PARAM_BLD_to_param(param_bld)
	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_ec, 0)
	if params == 0 || pctx == 0 {
		C.EC_POINT_free(point)
		C.BN_free(priv)
		C.EC_GROUP_free(group)
		C.OSSL_PARAM_BLD_free(param_bld)
		C.OSSL_PARAM_free(params)
		C.EVP_PKEY_free(pkey)
		if pctx == 0 {
			C.EVP_PKEY_CTX_free(pctx)
		}
		return error('EVP_PKEY_CTX_new or OSSL_PARAM_BLD_to_param failed')
	}

	p := C.EVP_PKEY_fromdata_init(pctx)
	q := C.EVP_PKEY_fromdata(pctx, &pkey, evp_pkey_keypair, params)
	if p <= 0 || q <= 0 {
		C.EC_POINT_free(point)
		C.BN_free(priv)
		C.EC_GROUP_free(group)
		C.OSSL_PARAM_BLD_free(param_bld)
		C.OSSL_PARAM_free(params)
		C.EVP_PKEY_free(pkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_fromdata(_init) failed')
	}

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

fn (pv PrivateKey) params() !string {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.EVP_PKEY_print_params(bo, pv.key, 2, 0)
	if n <= 0 {
		C.BIO_free_all(bo)
		return error('EVP_PKEY_print_params failed')
	}
	size := usize(0)
	mut m := C.BIO_read_ex(bo, 0, default_bioread_bufsize, &size)

	mut buf := []u8{len: int(size)}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	if m <= 0 {
		// explicitly free the buffer
		unsafe { buf.free() }
		C.BIO_free_all(bo)
		return error('BIO_read_ex failed')
	}

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
	// assert n == 1
	if n <= 0 {
		C.BIO_free_all(bo)
		return error('print private failed')
	}
	size := usize(0)
	mut m := C.BIO_read_ex(bo, 0, default_bioread_bufsize, &size)

	mut buf := []u8{len: int(size)}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	if m <= 0 {
		unsafe { buf.free() }
		C.BIO_free_all(bo)
		return error('BIO_read_ex failed')
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
	if n <= 0 {
		C.BN_free(bn)
		return []u8{}
	}
	// padded to curve key size
	cs := C.EVP_PKEY_get_bits(pv.key)
	padded := (cs + 7) / 8

	mut privkey := []u8{len: int(padded)}
	m := C.BN_bn2binpad(bn, privkey.data, padded)
	if m <= 0 {
		C.BN_free(bn)
		return error('BN_bn2binpad failed')
	}
	C.BN_free(bn)
	return privkey
}

// bytes gets bytes of encoded public key bytes
pub fn (pb PublicKey) bytes() ![]u8 {
	size := usize(default_point_bufsize)
	mut buf := []u8{len: int(size)}
	mut g := C.EVP_PKEY_get_octet_string_param(pb.key, voidptr('encoded-pub-key'.str),
		buf.data, buf.len, &size)
	if g <= 0 {
		unsafe { buf.free() }
		return error('EVP_PKEY_get_octet_string_param failed')
	}

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
	if n <= 0 {
		C.BIO_free_all(bo)
		return error('EVP_PKEY_print_public failed')
	}
	size := usize(0)
	mut m := C.BIO_read_ex(bo, 0, default_bioread_bufsize, &size)
	mut buf := []u8{len: int(size)}
	m = C.BIO_read_ex(bo, buf.data, buf.len, &size)
	if m <= 0 {
		C.BIO_free_all(bo)
		return error('BIO_read_ex failed')
	}

	output := buf[..size].clone()
	unsafe { buf.free() }
	C.BIO_free_all(bo)

	return output.bytestr()
}
