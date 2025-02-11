// Copyright (c) blackshirt. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module ecc

// Helpers
//
// default_digest gets the default digest (hash) algorithm for this key.
fn default_digest(key &C.EVP_PKEY) !&C.EVP_MD {
	// get bits size of this key
	bits_size := C.EVP_PKEY_get_bits(key)
	if bits_size <= 0 {
		return error(' this size isnt available.')
	}
	// based on this bits_size, choose appropriate digest algorithm
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

// sign_digest signs the digest with the key. Under the hood, EVP_PKEY_sign() does not
// hash the data to be signed, and therefore is normally used to sign digests.
fn sign_digest(key &C.EVP_PKEY, digest []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}
	sin := C.EVP_PKEY_sign_init(ctx)
	if sin != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign_init failed')
	}
	// siglen was used to store the size of the signature output. When EVP_PKEY_sign
	// was called with NULL signature buffer, siglen will tell maximum size of signature.
	siglen := usize(C.EVP_PKEY_size(key))
	st := C.EVP_PKEY_sign(ctx, 0, &siglen, digest.data, digest.len)
	if st <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Get null buffer length on EVP_PKEY_sign')
	}
	sig := []u8{len: int(siglen)}
	do := C.EVP_PKEY_sign(ctx, sig.data, &siglen, digest.data, digest.len)
	if do <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to sign message')
	}
	// siglen now contains actual length of the signature buffer.
	signed := sig[..siglen].clone()

	// Cleans up
	unsafe { sig.free() }
	C.EVP_PKEY_CTX_free(ctx)

	return signed
}

// verify_signature verifies the signature for the digest under the provided key.
fn verify_signature(key &C.EVP_PKEY, sig []u8, digest []u8) bool {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}
	vinit := C.EVP_PKEY_verify_init(ctx)
	if vinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}
	res := C.EVP_PKEY_verify(ctx, sig.data, sig.len, digest.data, digest.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}
	C.EVP_PKEY_CTX_free(ctx)
	return res == 1
}

// key_type_name returns the type name of the key, ie, `EC`, `DSA`, `RSA` or other value.
fn key_type_name(key &C.EVP_PKEY) !string {
	s := voidptr(C.EVP_PKEY_get0_type_name(key))
	if s == 0 {
		return error('fail to get type name')
	}
	tpname := unsafe { tos3(s) }
	return tpname
}

// key_description returns the human readable description from the key.
fn key_description(key &C.EVP_PKEY) !string {
	s := voidptr(C.EVP_PKEY_get0_description(key))
	if s == 0 {
		return error('fail to get key description')
	}
	desc := unsafe { tos3(s) }
	return desc
}

const default_groupname_bufsize = 25 // short name commonly only take 10-15 length

// key_group_name returns underlying group name of the key as a string.
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

// key_conversion_format gets point conversion format from the key.
fn key_conversion_format(key &C.EVP_PKEY) !int {
	n := C.EVP_PKEY_get_ec_point_conv_form(key)
	if n == 0 {
		return error('Get null conversion format')
	}
	return n
}

// ec_point_mult performs point multiplications, point = bn * generator
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

const default_point_bufsize = 160 // 2 * 64 + 1 + extra

fn point_2_buf(group &C.EC_GROUP, point &C.EC_POINT, fmt int) ![]u8 {
	ctx := C.BN_CTX_new()
	buf := []u8{len: default_point_bufsize}
	// EC_POINT_point2buf() allocates a buffer of suitable length and writes an EC_POINT to it in octet format.
	// The allocated buffer is written to *pbuf and its length is returned.
	// The caller must free up the allocated buffer with a call to OPENSSL_free().
	// Since the allocated buffer value is written to *pbuf the pbuf parameter MUST NOT be NULL.
	n := C.EC_POINT_point2buf(group, point, fmt, voidptr(&buf.data), ctx)
	if n <= 0 {
		C.BN_CTX_free(ctx)
		C.OPENSSL_free(voidptr(&buf.data))
		return error('Get null length of buf')
	}
	result := buf[..n].clone()
	C.OPENSSL_free(voidptr(buf.data))
	C.BN_CTX_free(ctx)
	return result
}
