module xecc

import crypto.sha256
import encoding.hex

fn test_create_private_key_from_bytes() ! {
	// Taken from https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#examples
	// Fixed data to represent the private and public key.
	priv_data := [u8(0xb9), 0x2f, 0x3c, 0xe6, 0x2f, 0xfb, 0x45, 0x68, 0x39, 0x96, 0xf0, 0x2a, 0xaf,
		0x6c, 0xda, 0xf2, 0x89, 0x8a, 0x27, 0xbf, 0x39, 0x9b, 0x7e, 0x54, 0x21, 0xc2, 0xa1, 0xe5,
		0x36, 0x12, 0x48, 0x5d]

	// UNCOMPRESSED FORMAT */
	pub_data := [u8(point_conversion_uncompressed), 0xcf, 0x20, 0xfb, 0x9a, 0x1d, 0x11, 0x6c, 0x5e,
		0x9f, 0xec, 0x38, 0x87, 0x6c, 0x1d, 0x2f, 0x58, 0x47, 0xab, 0xa3, 0x9b, 0x79, 0x23, 0xe6,
		0xeb, 0x94, 0x6f, 0x97, 0xdb, 0xa3, 0x7d, 0xbd, 0xe5, 0x26, 0xca, 0x07, 0x17, 0x8d, 0x26,
		0x75, 0xff, 0xcb, 0x8e, 0xb6, 0x84, 0xd0, 0x24, 0x02, 0x25, 0x8f, 0xb9, 0x33, 0x6e, 0xcf,
		0x12, 0x16, 0x2f, 0x5c, 0xcd, 0x86, 0x71, 0xa8, 0xbf, 0x1a, 0x47]

	pvkey := PrivateKey.from_bytes(priv_data)!
	assert pvkey.bytes()!.hex() == priv_data.hex()

	pbkey := pvkey.public_key()!
	assert pbkey.bytes()! == pub_data

	// Lets signing and verifying message
	msg := 'MessageTobeSigned'.bytes()
	signature := pvkey.sign(msg)!

	status := pbkey.verify(signature, msg)!
	assert status == true

	pvkey.free()
	pbkey.free()
}

fn test_prime256v1_curve_sign_verify_custom_hash() ! {
	// Key material generated from https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html
	// Samples for p256 key
	privdata := hex.decode('71905fb111cafbef42eb292ffdbee1ef74ed34b36d016e15e21478d072ef2e4f')!
	pubddata := hex.decode('04c82ae3fe911aa6cf7009261f95bacaf2fd4376985e90b8abb1795b1c8453a5ff39d5fb8864f9c050703e07b16c09b7d854b9351c3a88ac58bb7fe602bc5ab848')!
	// the tool only support sha256 and sha1 hash
	msg := 'aaa'.bytes()
	// signature created with SHA256
	signature := hex.decode('3045022100ea90dcb574fdeb18be7aefa37a07615ff65b03252838df16a5482baa6c4a8f1d02202506a7548cbebb238799c58e1a78f67455f1136366a09a6c3e867cbf3eebf880')!
	pvkey := PrivateKey.from_bytes(privdata)!

	pbkey := pvkey.public_key()!
	signed_default := pvkey.sign(msg)!

	// First case: sign and verify without prehash step
	sig0 := sign_without_prehash(pvkey.key, msg)!
	valid0 := verify_without_prehash(pbkey.key, sig0, msg)!
	dump(valid0 == true)
	// lets compares with pbkey.sign with no hash
	valid0_1 := pbkey.verify(sig0, msg, hash_config: .with_no_hash)!
	dump(valid0_1 == true)

	// Second case: sign and verify with sha256.sum direclty
	dgs1 := sha256.sum256(msg)
	sig1 := sign_without_prehash(pvkey.key, dgs1)!
	valid1 := verify_without_prehash(pbkey.key, sig1, dgs1)!
	dump(valid1 == true)
	// lets compares with pbkey.sign with no hash
	valid1_0 := pbkey.verify(sig1, dgs1, hash_config: .with_no_hash)!
	dump(valid1_0 == true)
	// lets compares signed_default with pbkey.sign default hash
	valid1_1 := pbkey.verify(signed_default, msg)!
	dump(valid1_1 == true)
	// lets compares sig1 with pbkey.sign default hash
	valid1_2 := pbkey.verify(sig1, msg)!
	dump(valid1_2 == true)

	// Third case: sign and verify with sha256.Digest
	mut d := sha256.new()
	_ := d.write(msg)!
	dgs2 := d.sum([]u8{})
	sig2 := sign_without_prehash(pvkey.key, dgs2)!
	valid2 := verify_without_prehash(pbkey.key, sig2, dgs2)!
	dump(valid2 == true)
	valid2_0 := pbkey.verify(sig2, dgs2, hash_config: .with_no_hash)!
	dump(valid2_0 == true)
	valid2_1 := pbkey.verify(sig2, msg)!
	dump(valid2_1 == true)

	// Fourth case: with default hash
	valid3 := pbkey.verify(signed_default, msg)!
	dump(valid3 == true)

	// Fiveth case: with custom hash, with sha256.Digest
	// TODO: need to be fixed
	opt := SignerOpts{
		hash_config: .with_custom_hash
	}
	sig4 := pvkey.sign(msg, opt)!
	dump(sig4.hex())
	valid4 := pbkey.verify(signed_default, msg, opt)!
	dump(valid4 == true)

	pvkey.free()
	pbkey.free()
}
