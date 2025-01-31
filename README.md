# ecc
The `v` ecdsa module based on standard `crypto.ecdsa` module,
but, its rewritten to use non-deprecated API on openssl 3.0.

## Contents
- [PrivateKey.from_bytes(bytes []u8, opt CurveOptions) !PrivateKey](#PrivateKey.from_bytes)
- [PrivateKey.from_string](#PrivateKey.from_string)
- [PrivateKey.new](#PrivateKey.new)
- [PublicKey.from_string](#PublicKey.from_string)
- [HashConfig](#HashConfig)
- [Nid](#Nid)
- [CurveOptions](#CurveOptions)
- [PrivateKey](#PrivateKey)
  - [bytes](#pvkey_bytes)
  - [dump_key](#pv_dump_key)
  - [free](#pv_free)
  - [public_key](#public_key)
  - [sign](#sign)
- [PublicKey](#PublicKey)
  - [bytes](#public_key_bytes)
  - [dump_key](#pb_dump_key)
  - [free](#pb_free)
  - [verify](#verify)
- [SignerOpts](#SignerOpts)

## PrivateKey.from_bytes
`PrivateKey.from_bytes` creates a new PrivateKey from provided bytes and options. The bytes length
should match with underlying curve key size intended to be created in options.

`PrivateKey.from_bytes(bytes []u8, opt CurveOptions) !PrivateKey`

Examples:
--------

```v
import ecc

const private_key_bytes = [u8(0xb9), 0x2f, 0x3c, 0xe6, 0x2f, 0xfb, 0x45, 0x68, 0x39, 0x96, 0xf0,
	0x2a, 0xaf, 0x6c, 0xda, 0xf2, 0x89, 0x8a, 0x27, 0xbf, 0x39, 0x9b, 0x7e, 0x54, 0x21, 0xc2, 0xa1,
	0xe5, 0x36, 0x12, 0x48, 0x5d]

fn main() {
	pvkey := ecc.PrivateKey.from_bytes(private_key_bytes)!
	assert pvkey.bytes()!.hex() == private_key_bytes.hex()
}
```

## PrivateKey.from_string
`PrivateKey.from_string` loads a PrivateKey from valid PEM-formatted string in s.

Example:
-------
```v
import ecc

const privatekey_sample = '-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAwzj2iiJZaxgk/C6mp
oVskdr6j7akl4bPB8JRnT1J5XNbLPK/iNd/BW+xUJEj/pxWhZANiAAT4/euEWRPV
9cdhtjcKlwF2HrFMLvgxAXFx+01UPfMQ9XOj/85qUhVq1jXraSyDy5FYF28UW4dn
04xVeRuPBbCFxc/uqYj2s5ItHcAZSV3L5sGlXadPfTqoIjCBQAx44k8=
-----END PRIVATE KEY-----'

fn main() {
	pkey := ecc.PrivateKey.from_string(privatekey_sample)!
}
```

## PrivateKey.new
[[Return to contents]](#Contents)

## PublicKey.from_string
[[Return to contents]](#Contents)

## HashConfig
[[Return to contents]](#Contents)

## Nid
[[Return to contents]](#Contents)

## CurveOptions
[[Return to contents]](#Contents)

## PrivateKey
[[Return to contents]](#Contents)

## pvkey_bytes
[[Return to contents]](#Contents)

## pv_dump_key
[[Return to contents]](#Contents)

## pv_free
[[Return to contents]](#Contents)

## public_key
[[Return to contents]](#Contents)

## sign
[[Return to contents]](#Contents)

## PublicKey
[[Return to contents]](#Contents)

## public_key_bytes
[[Return to contents]](#Contents)

## pb_dump_key
[[Return to contents]](#Contents)

## pb_free
[[Return to contents]](#Contents)

## verify
[[Return to contents]](#Contents)

## SignerOpts
[[Return to contents]](#Contents)