module xecc

import crypto.sha512

fn test_pvkey_new() ! {
	// creates prime256v1 key
	pkey := PrivateKey.new()!
	assert C.EVP_PKEY_get_bits(pkey.key) == 256
	assert C.EVP_PKEY_get_id(pkey.key) == nid_ec_publickey
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == 4
	assert C.EVP_PKEY_get_size(pkey.key) >= 2 * 32 // twice of key size
	assert get_key_type_name(pkey.key)! == 'EC' // its type of EC key
	assert get_key_description(pkey.key)! == 'OpenSSL EC implementation'
	assert get_group_name(pkey.key)! == sn_prime256v1 // prime256v1
	assert C.EVP_PKEY_get_security_bits(pkey.key) == 128

	pkey.free()
}

fn test_key_sign_n_verify_without_prehash() ! {
	pkey := PrivateKey.new()!
	pbkey := pkey.public_key()!
	msg := 'MessageTobeSigned'.bytes()

	sign_without_hashed := sign_without_prehash(pkey.key, msg)!
	assert verify_without_prehash(pbkey.key, sign_without_hashed, msg)! == true

	sign_nohash := pkey.sign(msg, hash_config: .with_no_hash)!
	assert verify_without_prehash(pbkey.key, sign_nohash, msg)! == true

	pkey.free()
	pbkey.free()
}

fn test_key_signing_n_verifying_with_default_hash() ! {
	pkey := PrivateKey.new()!
	pbkey := pkey.public_key()!
	msg := 'MessageTobeSigned'.bytes()

	sign_hashed := pkey.sign(msg)!
	assert pbkey.verify(sign_hashed, msg)! == true

	// with different curve
	pkey2 := PrivateKey.new(nid: .secp384r1)!
	pbkey2 := pkey2.public_key()!
	sign_hashed2 := pkey2.sign(msg)!
	assert pbkey2.verify(sign_hashed2, msg)! == true

	pkey.free()
	pkey2.free()
	pbkey.free()
	pbkey2.free()
}

fn test_key_signing_n_verifying_with_custom_hash() ! {
	pkey := PrivateKey.new()!
	pbkey := pkey.public_key()!
	msg := 'MessageTobeSigned'.bytes()

	mut opt := SignerOpts{
		hash_config: .with_custom_hash
		custom_hash: sha512.new()
	}
	digest_with_custom_hash := opt.custom_hash.sum(msg)
	signature_prehashed := sign_without_prehash(pkey.key, digest_with_custom_hash)!
	assert verify_without_prehash(pbkey.key, signature_prehashed, digest_with_custom_hash)! == true
	assert pbkey.verify(signature_prehashed, msg, opt)! == true

	signed := pkey.sign(msg, opt)!
	assert pbkey.verify(signed, msg, opt)! == true

	pkey.free()
	pbkey.free()
}
