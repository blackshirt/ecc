// Copyright (c) blackshirt. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module ecc

// This file contains utility to load PrivateKey and PublicKey
// from PEM formatted string.

// PrivateKey.from_string loads a PrivateKey from valid PEM-formatted string in s.
pub fn PrivateKey.from_string(s string) !PrivateKey {
	if s.len == 0 {
		return error('null string was not allowed')
	}
	bo := C.BIO_new(C.BIO_s_mem())
	if bo == 0 {
		return error('Failed to create BIO_new')
	}
	n := C.BIO_write(bo, s.str, s.len)
	if n <= 0 {
		return error('Failed BIO_write')
	}
	evpkey := C.PEM_read_bio_PrivateKey(bo, 0, 0, 0)
	if evpkey == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return error('Error loading key')
	}

	// Get the NID of this key, and check if the key object was
	// have the correct NID of ec public key type, ie, NID_X9_62_id_ecPublicKey
	nid := C.EVP_PKEY_get_id(evpkey)
	if nid != nid_ec_publickey {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return error('Get an nid of non ecPublicKey')
	}
	pctx := C.EVP_PKEY_CTX_new(evpkey, 0)
	if pctx == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return error('EVP_PKEY_CTX_new failed')
	}
	// performs evpkey check
	nck := C.EVP_PKEY_check(pctx)
	if nck != 1 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return error('EVP_PKEY_check failed')
	}
	// Matching the supported group
	group_name := key_group_name(evpkey)!
	gc := group_str_to_charname(group_name)!
	if gc != sn_secp256k1 && gc != sn_secp384r1 && gc != sn_prime256v1 && gc != sn_prime256v1 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return error('Unsupported group')
	}
	// Cleans up
	C.BIO_free_all(bo)
	C.EVP_PKEY_CTX_free(pctx)

	// Its OK to return
	return PrivateKey{
		key: evpkey
	}
}

// PublicKey.from_string loads a PublicKey from valid PEM-formatted string in s.
pub fn PublicKey.from_string(s string) !PublicKey {
	if s.len == 0 {
		return error('Null length string was not allowed')
	}
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.BIO_write(bo, s.str, s.len)
	if bo == 0 || n <= 0 {
		C.BIO_free_all(bo)
		return error('BIO Failed')
	}
	evpkey := C.PEM_read_bio_PUBKEY(bo, 0, 0, 0)
	if evpkey == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return error('Error loading key')
	}
	// Get the NID of this key, and check if the key object was
	// have the correct NID of ec public key type, ie, NID_X9_62_id_ecPublicKey
	nid := C.EVP_PKEY_get_id(evpkey)
	if nid != nid_ec_publickey {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return error('Get an nid of non ecPublicKey')
	}
	pctx := C.EVP_PKEY_CTX_new(evpkey, 0)
	if pctx == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return error('EVP_PKEY_CTX_new failed')
	}
	// performs only public key check, when checked with EVP_PKEY_check
	// will fail because private key was not availables on this pem input.
	nck := C.EVP_PKEY_public_check(pctx)
	if nck != 1 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return error('EVP_PKEY_public_check failed')
	}
	// Matching the supported group
	group_name := key_group_name(evpkey)!
	gc := group_str_to_charname(group_name)!
	if gc != sn_secp256k1 && gc != sn_secp384r1 && gc != sn_prime256v1 && gc != sn_prime256v1 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return error('Unsupported group')
	}
	// Cleans up
	C.BIO_free_all(bo)
	C.EVP_PKEY_CTX_free(pctx)
	// Its OK to return
	return PublicKey{
		key: evpkey
	}
}
