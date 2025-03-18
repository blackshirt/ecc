# ecc
The `v` ecdsa module based on standard `crypto.ecdsa` module,
but, its rewritten to use non-deprecated API on openssl 3.0.

> [!WARNING]  
> Most of the functionality on this module has been ported into standard `crypto.ecdsa` module.
> Use the standard `crypto.ecdsa` module instead.

## Deviation from standard `crypto.ecdsa` module
- This module rewritten with high level API, thats mean, maybe its doesn't work with the old.
- This module doesn't supports for creating keys from arbitrary length of raw bytes (seed). Only the length matching with the key size was supported.
- Just supports for minimal API surfaces.

## API Documentations
- [PrivateKey](#PrivateKey)
  - [bytes](#PrivateKey.bytes)
  - [dump_key](#PrivateKey.dump_key)
  - [free](#PrivateKey.free)
  - [public_key](#PrivateKey.public_key)
  - [sign](#PrivateKey.sign)
- [PrivateKey.from_bytes](#PrivateKey.from_bytes)
- [PrivateKey.from_string](#PrivateKey.from_string)
- [PrivateKey.new](#PrivateKey.new)
- [PublicKey](#PublicKey)
  - [bytes](#PublicKey.bytes)
  - [dump_key](#PublicKey.dump_key)
  - [free](#PublicKey.free)
  - [verify](#verify)
- [PublicKey.from_string](#PublicKey.from_string)
- [HashConfig](#HashConfig)
- [Nid](#Nid)
- [CurveOptions](#CurveOptions)
- [SignerOpts](#SignerOpts)


## PrivateKey
PrivateKey represents ECDSA curve private key.

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

## PrivateKey.bytes
`bytes` gets underlying private key bytes

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
## PublicKey
PublicKey represents ECDSA public key part.

## PublicKey.bytes
`bytes` gets bytes of encoded public key bytes

## PublicKey.dump_key
`dump_key` represents public key in human readable string.

Example:
--------
```v
import ecc

const public_key_sample = '-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+P3rhFkT1fXHYbY3CpcBdh6xTC74MQFx
cftNVD3zEPVzo//OalIVatY162ksg8uRWBdvFFuHZ9OMVXkbjwWwhcXP7qmI9rOS
LR3AGUldy+bBpV2nT306qCIwgUAMeOJP
-----END PUBLIC KEY-----'

fn main() {
	pbkey := ecc.PublicKey.from_string(public_key_sample)!
	out := pbkey.dump_key()!
	dump(out)
	pbkey.free()
}
```
Produces something like this output:
```bash
  Public-Key: (384 bit)
  pub:
      04:f8:fd:eb:84:59:13:d5:f5:c7:61:b6:37:0a:97:
      01:76:1e:b1:4c:2e:f8:31:01:71:71:fb:4d:54:3d:
      f3:10:f5:73:a3:ff:ce:6a:52:15:6a:d6:35:eb:69:
      2c:83:cb:91:58:17:6f:14:5b:87:67:d3:8c:55:79:
      1b:8f:05:b0:85:c5:cf:ee:a9:88:f6:b3:92:2d:1d:
      c0:19:49:5d:cb:e6:c1:a5:5d:a7:4f:7d:3a:a8:22:
      30:81:40:0c:78:e2:4f
  ASN1 OID: secp384r1
  NIST CURVE: P-384
```

## PublicKey.free
`free` releases the memory occupied by this key.

## verify
verify verifies the signature whether this signature were a valid one for the message
signed under the key and provided options. Its accepts options in opt to drive verify operation.
As a note, verifying signature with options differs from the options used by the signing produces,
would produce unmatching value (false).
Dont forget to call `.free()` after you finished your work with the key

Signature: `fn (pb PublicKey) verify(signature []u8, msg []u8, opt SignerOpts) !bool`

## SignerOpts
SignerOpts represents configuration options to drive signing and verifying process.
Its currently supports three different scheme, in the form of `hash_config` config:
- `with_default_hash`

   	Its a default behaviour. By setting to this value means the signing (or verifying)
	routine would do precomputing the hash (digest) of the message before signing (or verifying).
	The default hash algorithm was choosen based on the size of underlying key,
- `with_no_hash`

	When using this option, the signing (or verifying) routine does not perform any prehashing
	step to the message, and left message as is. Its also applied to messages that are already
	in the form of digests, which are produced outside of context.
- `with_custom_hash`

	By setting `hash_config` into this value, its allow custom hashing routine through of
	`hash.Hash` interface. By default its set to `sha256.Digest`. If you need the other one,
	make sure you set `custom_hash` it into your desired hash. When you choose `custom_hash` that
	produces hash smaller size than current key size, by default its not allowed.
	You should set `allow_smaller_size` into `true` explicitly to allow this limit.
	As a important note, hashing into smaller size was not recommended.

```codeblock
@[params]
pub struct SignerOpts {
pub mut:
	hash_config        HashConfig = .with_default_hash
	allow_smaller_size bool
	custom_hash        &hash.Hash = sha256.new()
}
```

## HashConfig
Config of hashing way in signing (verifying) process.
See `SignerOpts` options for more detail.
```codeblock
pub enum HashConfig {
	with_default_hash
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
