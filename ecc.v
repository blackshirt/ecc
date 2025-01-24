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

// enum of supported curve(s)
pub enum Nid {
	prime256v1
	secp384r1
	secp521r1
	secp256k1
}

fn (n Nid) to_int() int {
	match n {
		.prime256v1 { return nid_prime256v1 }
		.secp384r1 { return nid_secp384r1 }
		.secp521r1 { return nid_secp521r1 }
		.secp256k1 { return nid_secp256k1 }
	}
}

fn (n Nid) str() string {
	match n {
		.prime256v1 { return sn_prime256v1 }
		.secp384r1 { return sn_secp384r1 }
		.secp521r1 { return sn_secp521r1 }
		.secp256k1 { return sn_secp256k1 }
	}
}

// CurveOptions was an options for driving of the key creation.
@[params]
pub struct CurveOptions {
pub mut:
	// default to NIST P-256 curve
	nid Nid = .prime256v1
}

// Config of hashing way in signing (verifying) process.
// See `SignerOpts` options for more detail.
pub enum HashConfig {
	with_recommended_hash
	with_no_hash
	with_custom_hash
}

// SignerOpts was configuration options to drive signing and verifying process.
// Its currently supports three different scheme, in the form of `hash_config` config:
// - `with_recommended_hash`
//	 Its a default behaviour. By setting to this value means the signing (or verifying)
//   routine would do precomputing the hash (digest) of the message before signing (or verifying).
//   The default hash algorithm was choosen based on the size of underlying key,
// - `with_no_hash`
//   When using this option, the signing (or verifying) routine does not perform any prehashing
//   step to the message, and left message as is. Its also applied to messages that are already
//   in the form of digests, which are produced outside of context.
// - `with_custom_hash`
//   By setting `hash_config` into this value, its allow custom hashing routine through of
//   `hash.Hash` interface. By default its set to `sha256.Digest`. If you need the other one,
//   make sure you set `custom_hash` it into your desired hash. When you choose `custom_hash` that
//   produces hash smaller size than current key size, by default its not allowed.
//   You should set `allow_smaller_size` into `true` explicitly to allow this limit.
//	 As a important note, hashing into smaller size was not recommended.
@[params]
pub struct SignerOpts {
pub mut:
	hash_config        HashConfig = .with_recommended_hash
	allow_smaller_size bool
	custom_hash        &hash.Hash = sha256.new()
}

// PrivateKey represents ECDSA curve private key.
pub struct PrivateKey {
	key &C.EVP_PKEY
}

// PrivateKey.new creates a new PrivateKey. Its default to prime256v1 key.
// Dont forget to call `.free()` after finish with your key to prevent memleak.
pub fn PrivateKey.new(opt CurveOptions) !PrivateKey {
	// we default to NIST P-256 prime256v1 curve.
	mut nid := Nid.prime256v1
	match opt.nid {
		.prime256v1 {}
		.secp384r1 {
			nid = .secp384r1
		}
		.secp521r1 {
			nid = .secp521r1
		}
		.secp256k1 {
			nid = .secp256k1
		}
	}
	group := nid.str()
	pkey := C.EVP_EC_gen(group.str)
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
	if opt.hash_config == .with_no_hash {
		return sign_without_prehash(pv.key, msg)
	}
	// signing the message with provided custom hash
	if opt.hash_config == .with_custom_hash {
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
	if opt.hash_config == .with_no_hash {
		return verify_without_prehash(pb.key, signature, msg)
	}
	if opt.hash_config == .with_custom_hash {
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
