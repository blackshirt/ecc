module xecc

import crypto.sha1
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
	privdata := hex.decode('882048fcdce8d6da649b92f2b6b26d7d7aeee7da605a6f3772ca7b86d56b16ba')!
	pubddata := hex.decode('04b6a24f68639b8b4f925ae019022090ac34457f9ab3bfe99738f284455de9512097863b87fa7712edca68e63ac2188efe60273a46d5b8b709c462faa051668e6a')!
	// the tool only support sha256 and sha1 hash
	msg := 'aaa'.bytes()
	// signature created with SHA256
	signature := hex.decode('3045022045e3228132c3fd889b110599786d9536deaf8647a6cf886710e62ab5ad56164d0221008ad95a4218d364e57e0843b7e9d04312955a1e001b4295dce4805de00b1e36e1')!
	pvkey := PrivateKey.from_bytes(privdata)!

	pbkey := pvkey.public_key()!
	signed_default := pvkey.sign(msg)!

	// 1st case: sign and verify without prehash step
	sig0 := sign_digest(pvkey.key, msg)!
	valid0 := verify_signature(pbkey.key, sig0, msg)
	assert valid0 == true
	// lets compares with pbkey.sign with no hash
	opt0 := SignerOpts{
		hash_config: .with_no_hash
	}
	valid0_1 := pbkey.verify(sig0, msg, opt0)!
	assert valid0_1 == true

	// 2nd case: sign and verify with sha256.sum direclty
	dgs1 := sha256.sum256(msg)
	sig1 := sign_digest(pvkey.key, dgs1)!
	valid1 := verify_signature(pbkey.key, sig1, dgs1)
	assert valid1 == true
	// lets compares with pbkey.sign with no hash
	valid1_0 := pbkey.verify(sig1, dgs1, hash_config: .with_no_hash)!
	assert valid1_0 == true
	// lets compares signed_default with pbkey.sign default hash
	valid1_1 := pbkey.verify(signed_default, msg)!
	assert valid1_1 == true
	// lets compares sig1 with pbkey.sign default hash
	valid1_2 := pbkey.verify(sig1, msg)!
	assert valid1_2 == true

	// Third case: sign and verify with sha256.Digest
	mut d := sha256.new()
	_ := d.write(msg)!
	dgs2 := d.sum([]u8{})
	sig2 := sign_digest(pvkey.key, dgs2)!
	valid2 := verify_signature(pbkey.key, sig2, dgs2)
	assert valid2 == true

	valid2_0 := pbkey.verify(sig2, dgs2, hash_config: .with_no_hash)!
	assert valid2_0 == true
	valid2_1 := pbkey.verify(sig2, msg)!
	assert valid2_1 == true

	// 4th case: with default hash
	valid3 := pbkey.verify(signed_default, msg)!
	assert valid3 == true

	// 5th case: with custom hash, with sha1.Digest
	signed_with_sha1 := hex.decode('3046022100e180b8cc451917fb73eecdb05ef4682f2d2a98e33189b8b11cab1f06b2c497fe022100b65c2a5979da9bca18a0f045f98297f6b423baad9ff07adf3ec326117b98675d')!
	opt := SignerOpts{
		hash_config:        .with_custom_hash
		allow_smaller_size: true
		custom_hash:        sha1.new()
	}

	sig4 := pvkey.sign(msg, opt)!
	valid4 := pbkey.verify(sig4, msg, opt)!
	assert valid4 == true
	valid5 := pbkey.verify(signed_with_sha1, msg, opt)!
	assert valid5 == true

	pvkey.free()
	pbkey.free()
}
