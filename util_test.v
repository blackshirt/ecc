module xecc

import encoding.hex

// This material wss generated with https://emn178.github.io/online-tools/ecdsa/key-generator
// with curve SECG secp384r1 aka NIST P-384
const privatekey_sample = '-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAwzj2iiJZaxgk/C6mp
oVskdr6j7akl4bPB8JRnT1J5XNbLPK/iNd/BW+xUJEj/pxWhZANiAAT4/euEWRPV
9cdhtjcKlwF2HrFMLvgxAXFx+01UPfMQ9XOj/85qUhVq1jXraSyDy5FYF28UW4dn
04xVeRuPBbCFxc/uqYj2s5ItHcAZSV3L5sGlXadPfTqoIjCBQAx44k8=
-----END PRIVATE KEY-----'

const public_key_sample = '-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+P3rhFkT1fXHYbY3CpcBdh6xTC74MQFx
cftNVD3zEPVzo//OalIVatY162ksg8uRWBdvFFuHZ9OMVXkbjwWwhcXP7qmI9rOS
LR3AGUldy+bBpV2nT306qCIwgUAMeOJP
-----END PUBLIC KEY-----'

// Message tobe signed and verified
const message_tobe_signed = 'Example of ECDSA with P-384'.bytes()
// Message signature created with SHA384 digest with associated above key
const expected_signature = hex.decode('3066023100b08f6ec77bb319fdb7bce55a2714d7e79cc645d834ee539d8903cfcc88c6fa90df1558856cb840b2dd82e82cd89d7046023100d9d482ca8a6545a3b081fbdd4bb9643a2b4eda4e21fd624833216596032471faae646891f8d2f0bbb86b796c36d3c390')!

// above pem-formatted private key read with
// `$openssl ec -in vlib/crypto/ecdsa/example.pem -text -param_out -check`
// produces following result:
// ```codeblock
// read EC key
// Private-Key: (384 bit)
// priv:
//    30:ce:3d:a2:88:96:5a:c6:09:3f:0b:a9:a9:a1:5b:
//    24:76:be:a3:ed:a9:25:e1:b3:c1:f0:94:67:4f:52:
//    79:5c:d6:cb:3c:af:e2:35:df:c1:5b:ec:54:24:48:
//    ff:a7:15
// pub:
//    04:f8:fd:eb:84:59:13:d5:f5:c7:61:b6:37:0a:97:
//    01:76:1e:b1:4c:2e:f8:31:01:71:71:fb:4d:54:3d:
//    f3:10:f5:73:a3:ff:ce:6a:52:15:6a:d6:35:eb:69:
//    2c:83:cb:91:58:17:6f:14:5b:87:67:d3:8c:55:79:
//    1b:8f:05:b0:85:c5:cf:ee:a9:88:f6:b3:92:2d:1d:
//    c0:19:49:5d:cb:e6:c1:a5:5d:a7:4f:7d:3a:a8:22:
//    30:81:40:0c:78:e2:4f
// ASN1 OID: secp384r1
// NIST CURVE: P-384
// EC Key valid.
// writing EC key
// -----BEGIN EC PRIVATE KEY-----
// MIGkAgEBBDAwzj2iiJZaxgk/C6mpoVskdr6j7akl4bPB8JRnT1J5XNbLPK/iNd/B
// W+xUJEj/pxWgBwYFK4EEACKhZANiAAT4/euEWRPV9cdhtjcKlwF2HrFMLvgxAXFx
// +01UPfMQ9XOj/85qUhVq1jXraSyDy5FYF28UW4dn04xVeRuPBbCFxc/uqYj2s5It
// HcAZSV3L5sGlXadPfTqoIjCBQAx44k8=
// -----END EC PRIVATE KEY-----
// ```
fn test_load_privkey_from_string_sign_and_verify() ! {
	pkey := PrivateKey.from_string(privatekey_sample)!
	// public key part	
	pbkey := pkey.public_key()!
	// lets sign the message with default hash, ie, sha384
	signature := pkey.sign(message_tobe_signed)!

	verified := pbkey.verify(signature, message_tobe_signed)!
	assert verified == true
	pkey.free()
	pbkey.free()
}

// test for loading privat key from unsupported curve should fail.
fn test_load_privkey_from_string_with_unsupported_curve() ! {
	// generated with openssl ecparam -name secp192k1 -genkey -noout -out key.pem
	key := '-----BEGIN EC PRIVATE KEY-----
MFwCAQEEGDHV+WhJL2UjUhgMLh52k0RJjRebtu4HvqAHBgUrgQQAH6E0AzIABFyF
UHhnmmVRraSwrVkPdYIeXhH/Ob4+8OLcwrQBMv4RXsD1GVFsgkvEYDTEb/vnMA==
-----END EC PRIVATE KEY-----'
	_ := PrivateKey.from_string(key) or {
		assert err == error('Unsupported group')
		return
	}
}

fn test_load_pubkey_from_string_and_used_for_verifying() ! {
	pbkey := PublicKey.from_string(public_key_sample)!
	// expected signature was comes from hashed message with sha384
	status := pbkey.verify(expected_signature, message_tobe_signed)!
	assert status == true
	pbkey.free()
}
