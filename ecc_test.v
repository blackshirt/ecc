module xecc

import crypto.sha512

fn test_pvkey_new_p256() ! {
	// creates prime256v1 key
	pkey := PrivateKey.new()!
	assert C.EVP_PKEY_get_bits(pkey.key) == 256
	assert C.EVP_PKEY_get_id(pkey.key) == nid_ec_publickey
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == 4
	assert C.EVP_PKEY_size(pkey.key) >= 2 * 32 // twice or more of key size
	assert key_type_name(pkey.key)! == 'EC' // its type of EC key
	assert key_description(pkey.key)! == 'OpenSSL EC implementation'
	assert key_group_name(pkey.key)! == sn_prime256v1 // prime256v1
	assert C.EVP_PKEY_get_security_bits(pkey.key) == 128
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == point_conversion_uncompressed
	pkey.free()
}

fn test_pvkey_new_secp256k1() ! {
	// creates secp256k1 key
	pkey := PrivateKey.new(nid: .secp256k1)!
	assert C.EVP_PKEY_get_bits(pkey.key) == 256
	assert C.EVP_PKEY_get_id(pkey.key) == nid_ec_publickey
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == 4
	assert C.EVP_PKEY_size(pkey.key) >= 2 * 32 // twice or more of key size
	assert key_type_name(pkey.key)! == 'EC' // its type of EC key
	assert key_description(pkey.key)! == 'OpenSSL EC implementation'
	assert key_group_name(pkey.key)! == sn_secp256k1 // secp256k1
	assert C.EVP_PKEY_get_security_bits(pkey.key) == 128
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == point_conversion_uncompressed
	pkey.free()
}

fn test_pvkey_new_p384() ! {
	// creates secp384r1 key
	pkey := PrivateKey.new(nid: .secp384r1)!
	assert C.EVP_PKEY_get_bits(pkey.key) == 384
	assert C.EVP_PKEY_get_id(pkey.key) == nid_ec_publickey
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == 4
	assert C.EVP_PKEY_size(pkey.key) >= 2 * 48 // twice or more of key size
	assert key_type_name(pkey.key)! == 'EC' // its type of EC key
	assert key_description(pkey.key)! == 'OpenSSL EC implementation'
	assert key_group_name(pkey.key)! == sn_secp384r1 // secp384r1
	assert C.EVP_PKEY_get_security_bits(pkey.key) == 192
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == point_conversion_uncompressed
	pkey.free()
}

fn test_pvkey_new_p521() ! {
	// creates secp521r1 key
	pkey := PrivateKey.new(nid: .secp521r1)!
	assert C.EVP_PKEY_get_bits(pkey.key) == 521
	assert C.EVP_PKEY_get_id(pkey.key) == nid_ec_publickey
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == 4
	assert C.EVP_PKEY_size(pkey.key) >= 2 * 64 // twice or more of key size
	assert key_type_name(pkey.key)! == 'EC' // its type of EC key
	assert key_description(pkey.key)! == 'OpenSSL EC implementation'
	assert key_group_name(pkey.key)! == sn_secp521r1 // secp521r1
	assert C.EVP_PKEY_get_security_bits(pkey.key) == 256
	assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == point_conversion_uncompressed
	pkey.free()
}

fn test_key_sign_n_verify_without_prehash() ! {
	pkey := PrivateKey.new()!
	pbkey := pkey.public_key()!
	msg := 'MessageTobeSigned'.bytes()

	sign_without_hashed := sign_without_prehash(pkey.key, msg)!
	assert verify_without_prehash(pbkey.key, sign_without_hashed, msg)! == true

	sign_nohash := pkey.sign(msg, hash_config: .with_no_hash)!
	assert pbkey.verify(sign_nohash, msg, hash_config: .with_no_hash)! == true
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
	// equal of sha512.sum512(msg)
	_ := opt.custom_hash.write(msg)!
	digest_with_custom_hash := opt.custom_hash.sum([]u8{})
	signature_prehashed := sign_without_prehash(pkey.key, digest_with_custom_hash)!
	assert verify_without_prehash(pbkey.key, signature_prehashed, digest_with_custom_hash)! == true
	assert pbkey.verify(signature_prehashed, msg, opt)! == true

	signed := pkey.sign(msg, opt)!
	assert pbkey.verify(signed, msg, opt)! == true

	pkey.free()
	pbkey.free()
}
