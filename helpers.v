module xecc

// Helpers
//
// default_digest gets the default algorithm for this key.
fn default_digest(key &C.EVP_PKEY) !&C.EVP_MD {
	// get bits size of this key
	bits_size := C.EVP_PKEY_get_bits(key)
	if bits_size <= 0 {
		return error(' this size isnt available.')
	}
	// based on this bits_size, choose appropriate digest
	match true {
		bits_size <= 256 {
			return voidptr(C.EVP_sha256())
		}
		bits_size > 256 && bits_size <= 384 {
			return voidptr(C.EVP_sha384())
		}
		bits_size > 384 {
			return voidptr(C.EVP_sha512())
		}
		else {
			return error('Unsupported bits size')
		}
	}
	return error('should not here')
}

// sign the message with the key without pre-hashing, left the message as is.
// You can treat if the msg was also digest output from other process.
fn sign_without_prehash(key &C.EVP_PKEY, msg []u8) ![]u8 {
	if key == unsafe { nil } {
		return error('nil key')
	}
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Fails on EVP_PKEY_CTX_new')
	}
	sin := C.EVP_PKEY_sign_init(ctx)
	if sin != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('fails on EVP_PKEY_sign_init')
	}
	// siglen to store the size of the signature
	mut siglen := usize(0)
	// when EVP_PKEY_sign called with NULL sig, siglen will tell maximum size
	// of signature.
	st := C.EVP_PKEY_sign(ctx, 0, &siglen, msg.data, msg.len)
	if st != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Get null buffer length on EVP_PKEY_sign')
	}
	sig := []u8{len: int(siglen)}
	do := C.EVP_PKEY_sign(ctx, sig.data, &siglen, msg.data, msg.len)
	if do != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to sign message')
	}
	// siglen now contains actual length of the sig buffer.
	signed := sig[..siglen].clone()

	// Cleans up
	unsafe { sig.free() }
	C.EVP_PKEY_CTX_free(ctx)

	return signed
}

// verify_without_prehash verifies the signature for the message under the provided key.
fn verify_without_prehash(key &C.EVP_PKEY, sig []u8, msg []u8) !bool {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Fails on EVP_PKEY_CTX_new')
	}
	vinit := C.EVP_PKEY_verify_init(ctx)
	if vinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('fails on EVP_PKEY_verify_init')
	}
	res := C.EVP_PKEY_verify(ctx, sig.data, sig.len, msg.data, msg.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Failed to verify signature')
	}
	C.EVP_PKEY_CTX_free(ctx)
	return res == 1
}

// get type name of the key.
// Its return type of the key, ie, `EC`, `DSA`, `RSA` or other value.
fn key_type_name(key &C.EVP_PKEY) !string {
	s := voidptr(C.EVP_PKEY_get0_type_name(key))
	if s == 0 {
		return error('fail to get type name')
	}
	tpname := unsafe { tos3(s) }
	return tpname
}

// get the human readable description from the key.
fn key_description(key &C.EVP_PKEY) !string {
	s := voidptr(C.EVP_PKEY_get0_description(key))
	if s == 0 {
		return error('fail to get key description')
	}
	desc := unsafe { tos3(s) }
	return desc
}

const default_groupname_bufsize = 25 // short name commonly only take 10-15 length
// key_group_name gets the underlying group of the key as a string.
fn key_group_name(key &C.EVP_PKEY) !string {
	gname := []u8{len: default_groupname_bufsize}
	gname_len := usize(0)
	mut s := C.EVP_PKEY_get_group_name(key, gname.data, u32(gname.len), &gname_len)
	if s == 0 {
		unsafe { gname.free() }
		return error('fail to get group name')
	}
	group := gname[..gname_len].clone().bytestr()
	unsafe { gname.free() }
	return group
}

fn key_conversion_format(key &C.EVP_PKEY) !int {
	n := C.EVP_PKEY_get_ec_point_conv_form(key)
	if n == 0 {
		return error('Get null conversion format')
	}
	return n
}

fn ec_point_mult(group &C.EC_GROUP, bn &C.BIGNUM) !&C.EC_POINT {
	// Create a new EC_POINT object for the public key
	point := C.EC_POINT_new(group)
	// Create a new BN_CTX object for efficient BIGNUM operations
	ctx := C.BN_CTX_new()
	if ctx == 0 {
		C.EC_POINT_free(point)
		C.BN_CTX_free(ctx)
		return error('Failed to create BN_CTX')
	}

	// Perform the point multiplication to compute the public key: point = bn * G
	res := C.EC_POINT_mul(group, point, bn, 0, 0, ctx)
	if res != 1 {
		C.EC_POINT_free(point)
		C.BN_CTX_free(ctx)
		return error('Failed to compute public key')
	}
	C.BN_CTX_free(ctx)
	return point
}

const default_pointconv_bufsize = 160 // 2 * 64 + 1 + extra

fn point_2_buf(group &C.EC_GROUP, point &C.EC_POINT, fmt int) ![]u8 {
	ctx := C.BN_CTX_new()
	buf := []u8{len: default_pointconv_bufsize}
	n := C.EC_POINT_point2buf(group, point, fmt, voidptr(&buf.data), ctx)
	if n <= 0 {
		C.BN_CTX_free(ctx)
		C.OPENSSL_free(voidptr(&buf.data))
		return error('Get null length of buf')
	}
	// mut dst := []u8{len: n}
	//_ := copy(mut dst, buf)
	result := buf[..n].clone()
	C.OPENSSL_free(voidptr(buf.data))
	C.BN_CTX_free(ctx)
	return result
}
