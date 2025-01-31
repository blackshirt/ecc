# ecc
The `v` ecdsa module based on standard `crypto.ecdsa` module,
but, its rewritten to use non-deprecated API on openssl 3.0.

## API Documentations
- [PrivateKey.from_bytes](#PrivateKey.from_bytes)
- [PrivateKey.from_string](#PrivateKey.from_string)
- [PrivateKey.new](#PrivateKey.new)
- [PublicKey.from_string](#PublicKey.from_string)
- [HashConfig](#HashConfig)
- [Nid](#Nid)
- [CurveOptions](#CurveOptions)
- [PrivateKey](#PrivateKey)
  - [bytes](#PrivateKey.bytes)
  - [dump_key](#PrivateKey.dump_key)
  - [free](#PrivateKey.free)
  - [public_key](#PrivateKey.public_key)
  - [sign](#PrivateKey.sign)
- [PublicKey](#PublicKey)
  - [bytes](#PublicKey.bytes)
  - [dump_key](#PublicKey.dump_key)
  - [free](#PublicKey.free)
  - [verify](#verify)
- [SignerOpts](#SignerOpts)

## PrivateKey.from_bytes
`fn PrivateKey.from_bytes(bytes []u8, opt CurveOptions) !PrivateKey`

`PrivateKey.from_bytes` creates a new PrivateKey from provided bytes and options. The bytes length
should match with underlying curve key size intended to be created in options.

Example:
--------
```v
import ecc

const private_key_bytes = [u8(0xb9), 0x2f, 0x3c, 0xe6, 0x2f, 0xfb, 0x45, 0x68, 0x39, 0x96, 0xf0,
	0x2a, 0xaf, 0x6c, 0xda, 0xf2, 0x89, 0x8a, 0x27, 0xbf, 0x39, 0x9b, 0x7e, 0x54, 0x21, 0xc2, 0xa1,
	0xe5, 0x36, 0x12, 0x48, 0x5d]

fn main() {
	pvkey := ecc.PrivateKey.from_bytes(private_key_bytes)!
	// use your key
	//
	// .... some works
	//
	// release it when you finish
	pvkey.free()
}
```

## PrivateKey.from_string
`fn PrivateKey.from_string(s string) !PrivateKey`

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
	// use your key
	//
	// .... some works
	//
	// release it when you finish
	pkey.free()
}
```

## PrivateKey.new
`fn PrivateKey.new(opt CurveOptions) !PrivateKey`

PrivateKey.new creates a new PrivateKey. Its default to prime256v1 key.
Dont forget to call `.free()` after finish with your key to prevent memleak.

Example:
--------
```v
import ecc

fn main() {
	// creates default prime256v1 key
	p256key := ecc.PrivateKey.new()!

	// or you can create another supported curve(s)
	psecp256k1key := ecc.PrivateKey.new(nid: .secp256k1)!
	p384key := ecc.PrivateKey.new(nid: .secp384r1)!
	p521key := ecc.PrivateKey.new(nid: .secp521r1)!

	// do some works with your key

	// free it after finish
	p256key.free()
	psecp256k1key.free()
	p384key.free()
	p521key.free()
}
```

## PublicKey.from_string
`PublicKey.from_string` loads a PublicKey from valid PEM-formatted string in s.

Function signature: `fn PublicKey.from_string(s string) !PublicKey`

Example:
-------
```v
import ecc

const public_key_sample = '-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+P3rhFkT1fXHYbY3CpcBdh6xTC74MQFx
cftNVD3zEPVzo//OalIVatY162ksg8uRWBdvFFuHZ9OMVXkbjwWwhcXP7qmI9rOS
LR3AGUldy+bBpV2nT306qCIwgUAMeOJP
-----END PUBLIC KEY-----'

fn main() {
	pbkey := ecc.PublicKey.from_string(public_key_sample)!
	// works with your public key

	// release it
	pbkey.free()
}
```

## HashConfig
Config of hashing way in signing (verifying) process.
See `SignerOpts` options for more detail.
```codeblock
pub enum HashConfig {
	with_recommended_hash
	with_no_hash
	with_custom_hash
}
```

## Nid
The enum of currently supported curve(s)
```codeblock
pub enum Nid {
	prime256v1
	secp384r1
	secp521r1
	secp256k1
}
```

## CurveOptions
CurveOptions was an options for driving of the key creation.
```codeblock
@[params]
pub struct CurveOptions {
pub mut:
	// default to NIST P-256 curve
	nid Nid = .prime256v1
}
```

## PrivateKey
PrivateKey represents ECDSA curve private key.

## PrivateKey.bytes
[[Return to contents]](#Contents)

## PrivateKey.dump_key
`dump_key` represents PrivateKey in human readable string.

Example:
-------
```v
import ecc

fn main() {
	pvkey := ecc.PrivateKey.new(nid: .secp384r1)!
	out := pvkey.dump_key()!
	dump(out)

	// ...
	pvkey.free()
}
```
Produces similar something like this output:
```bash
Private-Key: (384 bit)
  priv:
      1e:b1:cb:e6:83:42:e0:a3:33:24:de:ea:f7:54:53:
      40:c1:b4:9d:79:96:c9:b0:67:80:b4:65:b4:05:d7:
      cd:80:c9:c3:22:60:aa:10:82:c5:88:26:0a:f6:33:
      cd:f4:25
  pub:
      04:65:c1:53:95:39:b3:1d:6c:e3:c7:72:08:17:85:
      7b:05:77:ff:8f:6d:55:2b:e9:8e:68:3b:c0:cf:a5:
      12:89:78:30:bc:4c:cd:ff:fe:34:96:07:6c:73:ca:
      8a:c2:bc:90:37:f1:24:f5:5f:54:b3:6b:5f:05:b2:
      38:4b:4e:fd:e7:64:58:51:1a:a3:2b:07:50:8e:f6:
      24:92:33:2c:d6:d6:c0:3b:31:2d:a3:d8:46:48:7b:
      17:3e:0a:c6:0c:6c:21
  ASN1 OID: secp384r1
  NIST CURVE: P-384
  ```

## PrivateKey.free
`free` releases memory occupied by this key.

## PrivateKey.public_key
`public_key` gets the public key from this PrivateKey.

## PrivateKey.sign
`sign` signs the the message with the provided key and return the signature or error otherwise.
If you dont provide the options, by default, it will precompute the digest (hash)
of message before signing based on the size of underlying key.
See the `SignerOpts` for more detail of options.

Function signature: `fn (pv PrivateKey) sign(msg []u8, opt SignerOpts) ![]u8`

Example:
-------
```v
import ecc

fn main() {
	pkey := ecc.PrivateKey.new()!
	pbkey := pkey.public_key()!
	msg := 'MessageTobeSigned'.bytes()

	sign_hashed := pkey.sign(msg)!
	assert pbkey.verify(sign_hashed, msg)! == true

	pvkey.free()
	pbkey.free()
}
```

## PublicKey
PublicKey represents ECDSA public key part.

## PublicKey.bytes
[[Return to contents]](#Contents)

## pb_dump_key
[[Return to contents]](#Contents)

## pb_free
[[Return to contents]](#Contents)

## verify
[[Return to contents]](#Contents)

## SignerOpts
[[Return to contents]](#Contents)