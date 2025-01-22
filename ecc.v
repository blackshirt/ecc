module xecc

import hash
import crypto.sha256

// Constants of short name of the supported curve(s)
//
// #define SN_secp256k1            "secp256k1"
const sn_secp256k1 = 'secp256k1'
// #define SN_secp384r1            "secp384r1"
const sn_secp384r1 = 'secp384r1'
// #define SN_secp521r1            "secp521r1"
const sn_secp521r1 = 'secp521r1'
// #define SN_X9_62_prime256v1     "prime256v1"
const sn_prime256v1 = 'prime256v1'

// NIST P-256 prime256v1 curve (or secp256r1)
const nid_prime256v1 = C.NID_X9_62_prime256v1
// NIST P-384, ie, secp384r1 curve, defined as #define NID_secp384r1 715
const nid_secp384r1 = C.NID_secp384r1
// NIST P-521, ie, secp521r1 curve, defined as #define NID_secp521r1 716
const nid_secp521r1 = C.NID_secp521r1
// Bitcoin curve, defined as #define NID_secp256k1 714
const nid_secp256k1 = C.NID_secp256k1

// #define NID_X9_62_id_ecPublicKey   408
const nid_ec_publickey = C.NID_X9_62_id_ecPublicKey
// C.EVP_PKEY_EC = NID_X9_62_id_ecPublicKey
const nid_evp_pkey_ec = C.EVP_PKEY_EC

@[typedef]
struct C.EC_KEY {}

@[typedef]
struct C.EVP_PKEY {}

@[typedef]
struct C.EVP_PKEY_CTX {}

// CurveOptions was an options for driving of the key creation.
@[params]
pub struct CurveOptions {
pub mut:
	// default to NIST P-256 curve
	curve string = sn_prime256v1
}

pub enum HashOpts {
	with_default_hash
	with_no_prehash
	with_custom_hash
}

// SignerOpts was configuration options to drive signing and verifying process.
// Its currently supports three different scheme, in the form of `hash_opt` config:
// - `with_default_hash`
//	 Its a default behaviour. By setting to this value means the signing (or verifying)
//   routine would do precomputing the hash (digest) of the message before signing (or verifying).
//   The default hash algorithm was choosen based on the size of underlying key,
// - `with_no_prehash`
//   When using this option, the signing (or verifying) routine does not perform any prehashing
//   step to the message, and left message as is. Its also applied to messages that are already
//   in the form of digests, which are produced outside of context.
// - `with_custom_hash`
//   By setting `hash_opt` into this value, its allow custom hashing routine through of
//   `hash.Hash` interface. By default its set to `sha256.Digest`. If you need the other one,
//   make sure you set `custom_hash` it into your desired hash. When you choose `custom_hash` that
//   produces hash smaller size than current key size, by default its not allowed.
//   You should set `allow_smaller_size` into `true` explicitly to allow this limit.
//	 As a important note, hashing into smaller size was not recommended.
@[params]
pub struct SignerOpts {
pub mut:
	hash_opt           HashOpts = .with_default_hash
	allow_smaller_size bool
	custom_hash        &hash.Hash = sha256.new()
}

// PrivateKey represents ECDSA curve private key.
pub struct PrivateKey {
	key &C.EVP_PKEY
}

// PrivateKey.new creates a new PrivateKey. Dont forget to call `.free()`
// after finish with your key to prevent memleak.
pub fn PrivateKey.new(opt CurveOptions) !PrivateKey {
	// we default to NIST P-256 prime256v1 curve.
	mut cv := sn_prime256v1
	match opt.curve {
		sn_prime256v1 {}
		sn_secp384r1 {
			cv = sn_secp384r1
		}
		sn_secp521r1 {
			cv = sn_secp521r1
		}
		sn_secp256k1 {
			cv = sn_secp256k1
		}
		else {
			return error('Unsupported curve options')
		}
	}
	pkey := C.EVP_EC_gen(voidptr(cv.str))
	if pkey == 0 {
		C.EVP_PKEY_free(pkey)
		return error('C.EVP_EC_gen failed')
	}
	return PrivateKey{
		key: pkey
	}
}

// free releases memory occupied by this key.
pub fn (pv &PrivateKey) free() {
	C.EVP_PKEY_free(pv.key)
}

// int EVP_PKEY_set_bn_param(EVP_PKEY *pkey, const char *key_name, const BIGNUM *bn);
fn C.EVP_PKEY_set_bn_param(pkey &C.EVP_PKEY, key_name &u8, bn &C.BIGNUM) int

// int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *pkey, const unsigned char *pub, size_t publen);
fn C.EVP_PKEY_set1_encoded_public_key(pkey &C.EVP_PKEY, pub_data &u8, publen int) int

// size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *pkey, unsigned char **ppub);
fn C.EVP_PKEY_get1_encoded_public_key(pkey &C.EVP_PKEY, ppub &&u8) int

// public_key gets the public key of this PrivateKey.
// Its returns the duplicate of this key. Dont forget to call `.free()`
// on this public key if you've finished with them.
pub fn (pv PrivateKey) public_key() !PublicKey {
	bo := C.BIO_new(C.BIO_s_mem())
	n := C.i2d_PUBKEY_bio(bo, pv.key)
	assert n != 0

	pbkey := C.d2i_PUBKEY_bio(bo, 0)
	C.BIO_free_all(bo)

	return PublicKey{
		key: pbkey
	}
}

// sign signs the the message with the provided key and return the signature or error otherwise.
// If you dont provide the options, by default, it will precompute the digest (hash)
// of message before signing based on the size of underlying key.
// See the `SignerOpts` for more detail of options.
pub fn (pv PrivateKey) sign(msg []u8, opt SignerOpts) ![]u8 {
	if msg.len == 0 {
		return error('Null-length message was not allowed')
	}
	// signing the message without pre-hashing step
	if opt.hash_opt == .with_no_prehash {
		return sign_without_prehash(pv.key, msg)
	}
	// signing the message with provided custom hash
	if opt.hash_opt == .with_custom_hash {
		mut cfg := opt
		bits_size := C.EVP_PKEY_get_bits(pv.key)
		if bits_size <= 0 {
			return error(' bits_size wasnt availables.')
		}
		key_size := (bits_size + 7) / 8
		if cfg.custom_hash.size() < key_size {
			if !cfg.allow_smaller_size {
				return error('Hash into smaller size than current key size was not allowed')
			}
		}
		msg_digest := cfg.custom_hash.sum(msg)
		out := sign_without_prehash(pv.key, msg_digest)!

		return out
	}
	// Otherwise, use the default hashing based on the key size.
	ctx := C.EVP_MD_CTX_new()
	tipe := default_digest(pv.key)!
	init := C.EVP_DigestSignInit(ctx, 0, tipe, 0, pv.key)
	if init != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(tipe)
		return error('EVP_DigestSignInit failed')
	}
	upd := C.EVP_DigestSignUpdate(ctx, msg.data, msg.len)
	if upd != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(tipe)
		return error('EVP_DigestSignUpdate failed')
	}
	siglen := usize(0)
	f := C.EVP_DigestSignFinal(ctx, 0, &siglen)
	assert f != 0
	sig := []u8{len: int(siglen)}
	fin2 := C.EVP_DigestSignFinal(ctx, sig.data, &siglen)
	if fin2 != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(tipe)
		return error('EVP_DigestSignFinal 2 failed')
	}

	signed := sig[..int(siglen)].clone()
	// cleans up
	unsafe { sig.free() }
	C.EVP_MD_CTX_free(ctx)
	C.EVP_MD_free(tipe)

	return signed
}

// PublicKey
pub struct PublicKey {
	key &C.EVP_PKEY
}

// free releases the memory occupied by this key.
pub fn (pb &PublicKey) free() {
	C.EVP_PKEY_free(pb.key)
}

// verify verifies the signature whether this signature were a valid one for the message
// signed under the key and provided options. Its accepts options in opt to drive verify operation.
// As a note, verifying signature with options differs from the options used by the signing produces,
// would produce unmatching value (false).
// Dont forget to call `.free()` after you finished your work with the key.
pub fn (pb PublicKey) verify(signature []u8, msg []u8, opt SignerOpts) !bool {
	if msg.len == 0 {
		return error('Null-length message was not allowed')
	}
	if opt.hash_opt == .with_no_prehash {
		return verify_without_prehash(pb.key, signature, msg)
	}
	if opt.hash_opt == .with_custom_hash {
		mut cfg := opt
		bits_size := C.EVP_PKEY_get_bits(pb.key)
		if bits_size <= 0 {
			return error(' bits_size was invalid')
		}
		key_size := (bits_size + 7) / 8
		if cfg.custom_hash.size() < key_size {
			if !cfg.allow_smaller_size {
				return error('Hash into smaller size than current key size was not allowed')
			}
		}
		msg_digest := cfg.custom_hash.sum(msg)
		valid := verify_without_prehash(pb.key, signature, msg_digest)!

		return valid
	}
	ctx := C.EVP_MD_CTX_new()
	tipe := default_digest(pb.key)!
	init := C.EVP_DigestVerifyInit(ctx, 0, tipe, 0, pb.key)
	if init != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(tipe)
		return error('EVP_DigestVerifyInit failed')
	}
	upd := C.EVP_DigestVerifyUpdate(ctx, msg.data, msg.len)
	if upd != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(tipe)
		return error('EVP_DigestVerifyUpdate failed')
	}
	fin := C.EVP_DigestVerifyFinal(ctx, signature.data, signature.len)
	if fin != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(tipe)
		return error('EVP_DigestVerifyFinal failed')
	}
	C.EVP_MD_CTX_free(ctx)
	C.EVP_MD_free(tipe)

	return fin == 1
}

// Helpers
//
// default_digest gets the default digest opaque for this key.
fn default_digest(key &C.EVP_PKEY) !&C.EVP_MD {
	// get bits size of this key
	bits_size := C.EVP_PKEY_get_bits(key)
	if bits_size <= 0 {
		return error(' this size isnt available.')
	}
	// based on this bits_size, choose appropriate digest
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

// sign the message with the key without pre-hashing, left the message as is.
// You can treat if the msg was also digest output from other process.
fn sign_without_prehash(key &C.EVP_PKEY, msg []u8) ![]u8 {
	if key == unsafe { nil } {
		return error('nil key')
	}
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Fails on EVP_PKEY_CTX_new')
	}
	sin := C.EVP_PKEY_sign_init(ctx)
	if sin != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('fails on EVP_PKEY_sign_init')
	}
	// siglen to store the size of the signature
	mut siglen := usize(0)
	// when EVP_PKEY_sign called with NULL sig, siglen will tell maximum size
	// of signature.
	st := C.EVP_PKEY_sign(ctx, 0, &siglen, msg.data, msg.len)
	if st != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Get null buffer length on EVP_PKEY_sign')
	}
	sig := []u8{len: int(siglen)}
	do := C.EVP_PKEY_sign(ctx, sig.data, &siglen, msg.data, msg.len)
	if do != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to sign message')
	}
	// siglen now contains actual length of the sig buffer.
	signed := sig[..siglen].clone()

	// Cleans up
	unsafe { sig.free() }
	C.EVP_PKEY_CTX_free(ctx)

	return signed
}

// verify_without_prehash verifies the signature for the message under the provided key.
fn verify_without_prehash(key &C.EVP_PKEY, sig []u8, msg []u8) !bool {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Fails on EVP_PKEY_CTX_new')
	}
	vinit := C.EVP_PKEY_verify_init(ctx)
	if vinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('fails on EVP_PKEY_verify_init')
	}
	res := C.EVP_PKEY_verify(ctx, sig.data, sig.len, msg.data, msg.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('Failed to verify signature')
	}
	C.EVP_PKEY_CTX_free(ctx)
	return res == 1
}

// get type name of the key.
// Its return type of the key, ie, `EC`, `DSA`, `RSA` or other value.
fn get_key_type_name(key &C.EVP_PKEY) !string {
	s := voidptr(C.EVP_PKEY_get0_type_name(key))
	if s == 0 {
		return error('fail to get type name')
	}
	tpname := unsafe { tos3(s) }
	return tpname
}

// get the human readable description from the key.
fn get_key_description(key &C.EVP_PKEY) !string {
	s := voidptr(C.EVP_PKEY_get0_description(key))
	if s == 0 {
		return error('fail to get key description')
	}
	desc := unsafe { tos3(s) }
	return desc
}

// get_group_name gets the underlying group of the key as a string.
fn get_group_name(key &C.EVP_PKEY) !string {
	gname := []u8{len: 50}
	mut gname_len := usize(0)
	s := C.EVP_PKEY_get_group_name(key, gname.data, u32(gname.len), &gname_len)
	if s == 0 {
		return error('fail to get group name')
	}
	group := gname[..gname_len].clone().bytestr()
	unsafe { gname.free() }
	return group
}
