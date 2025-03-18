module ecc

import hash
import crypto.sha256

// Constants of shortname of the supported curve(s)
//
// #define SN_X9_62_prime256v1     "prime256v1"
const sn_prime256v1 = &char(C.SN_X9_62_prime256v1)
// #define SN_secp384r1            "secp384r1"
const sn_secp384r1 = &char(C.SN_secp384r1)
// #define SN_secp521r1            "secp521r1"
const sn_secp521r1 = &char(C.SN_secp521r1)
// #define SN_secp256k1            "secp256k1"
const sn_secp256k1 = &char(C.SN_secp256k1)

// Constants of internal ID of the groups (curves)
//
// NIST P-256 prime256v1 curve (or secp256r1)
const nid_prime256v1 = C.NID_X9_62_prime256v1
// NIST P-384, ie, secp384r1 curve, defined as #define NID_secp384r1 715
const nid_secp384r1 = C.NID_secp384r1
// NIST P-521, ie, secp521r1 curve, defined as #define NID_secp521r1 716
const nid_secp521r1 = C.NID_secp521r1
// Bitcoin curve, defined as #define NID_secp256k1 714
const nid_secp256k1 = C.NID_secp256k1

// Other defined constants.
//
// #define NID_X9_62_id_ecPublicKey   408
const nid_ec_publickey = C.NID_X9_62_id_ecPublicKey
// C.EVP_PKEY_EC = NID_X9_62_id_ecPublicKey
const nid_evp_pkey_ec = C.EVP_PKEY_EC
// flag for named curve
const openssl_ec_named_curve = C.OPENSSL_EC_NAMED_CURVE

// https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#selections
const evp_pkey_key_parameters = C.EVP_PKEY_KEY_PARAMETERS
const evp_pkey_public_key = C.EVP_PKEY_PUBLIC_KEY
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR

// POINT_CONVERSION FORAMT
const point_conversion_compressed = 2
const point_conversion_uncompressed = 4
const point_conversion_hybrid = 6

// Max of size of current supported digest
const max_digest_size = C.EVP_MAX_MD_SIZE

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
	with_default_hash
	with_no_hash
	with_custom_hash
}

// SignerOpts was configuration options to drive the signing and verifying process.
// Its currently supports for three of different schemes, in the form of `hash_config` option:
// - `with_default_hash`
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
//   You should explicitly set `allow_smaller_size` value into `true`  to overcome this limit.
//	 As a important note, hashing into smaller size was not recommended.
@[params]
pub struct SignerOpts {
pub mut:
	hash_config        HashConfig = .with_default_hash
	allow_smaller_size bool
	custom_hash        &hash.Hash = sha256.new()
}

// The enumerations of supported curve(s)
pub enum Nid {
	prime256v1 = C.NID_X9_62_prime256v1
	secp384r1  = C.NID_secp384r1
	secp521r1  = C.NID_secp521r1
	secp256k1  = C.NID_secp256k1
}

// PrivateKey represents ECDSA private key.
pub struct PrivateKey {
	key &C.EVP_PKEY
}

// PrivateKey.new creates a new PrivateKey. Its default to `prime256v1` key.
// Dont forget to call `.free()` after finish with your key to prevent memleak.
pub fn PrivateKey.new(opt CurveOptions) !PrivateKey {
	// New high level keypair generator
	evpkey := C.EVP_PKEY_new()
	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_ec, 0)
	if pctx == 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('C.EVP_PKEY_CTX_new_id failed')
	}
	nt := C.EVP_PKEY_keygen_init(pctx)
	if nt <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_keygen_init failed')
	}
	// set the group (curve) based on the NID
	cn := C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, int(opt.nid))
	if cn <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_CTX_set_ec_paramgen_curve_nid')
	}
	// explicitly set the named curve flag, likely its the default on 3.0.
	pn := C.EVP_PKEY_CTX_set_ec_param_enc(pctx, openssl_ec_named_curve)
	if pn <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_CTX_set_ec_param_enc failed')
	}
	// generates keypair
	nr := C.EVP_PKEY_keygen(pctx, &evpkey)
	if nr <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_keygen failed')
	}
	// Cleans up the context and return the key
	C.EVP_PKEY_CTX_free(pctx)
	return PrivateKey{
		key: evpkey
	}
}

// free releases memory occupied by this private key.
pub fn (pv &PrivateKey) free() {
	C.EVP_PKEY_free(pv.key)
}

// public_key returns the PublicKey part from this PrivateKey.
// Its returns the new public key with stripped off private key bits.
// Dont forget to call `.free()` on this public key if you've finished with them.
pub fn (pv PrivateKey) public_key() !PublicKey {
	// duplicates this key and strip off private bits
	// by replacing it with null-bignum
	pbkey := C.EVP_PKEY_dup(pv.key)
	bn := C.BN_new()
	n := C.EVP_PKEY_set_bn_param(pbkey, c'priv', bn)
	assert n == 1

	// cleans up
	C.BN_free(bn)

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
	bits_size := C.EVP_PKEY_get_bits(pv.key)
	if bits_size <= 0 {
		return error(' bits_size was invalid')
	}
	key_size := (bits_size + 7) / 8
	match opt.hash_config {
		.with_no_hash {
			// with `.with_no_hash` options, we treat a message as a digest directly.
			if msg.len > key_size || msg.len > max_digest_size {
				return error('Unmatching msg size, use .with_default_hash options instead')
			}
			if msg.len < key_size {
				if !opt.allow_smaller_size {
					return error('Use .allow_smaller_size option explicitly')
				}
			}
			return sign_digest(pv.key, msg)
		}
		.with_default_hash {
			// Otherwise, use the default hashing algortihm based on the key size.
			ctx := C.EVP_MD_CTX_new()
			md := default_digest(pv.key)!
			// initialize digest-ed signing operation
			init := C.EVP_DigestSignInit(ctx, 0, md, 0, pv.key)
			if init != 1 {
				C.EVP_MD_CTX_free(ctx)
				C.EVP_MD_free(md)
				return error('EVP_DigestSignInit failed')
			}
			siglen := usize(C.EVP_PKEY_size(pv.key))
			buf := []u8{len: int(siglen)}
			n := C.EVP_DigestSign(ctx, buf.data, &siglen, msg.data, msg.len)
			if n <= 0 {
				unsafe { buf.free() }
				C.EVP_MD_CTX_free(ctx)
				C.EVP_MD_free(md)
				return error('EVP_DigestSign failed')
			}
			sig := buf[..int(siglen)].clone()
			// cleans up
			unsafe { buf.free() }
			C.EVP_MD_CTX_free(ctx)
			C.EVP_MD_free(md)

			return sig
		}
		.with_custom_hash {
			// make a copy of option
			mut cfg := opt
			// when your digest output was smaller than the key size,
			// you should set the .allow_smaller_size option into true flag.
			// like the sha512 digest, where the digest output was 64 bytes long, with P-256 curve
			// where the key size was 66 bytes, you need to set the option correctly.
			if cfg.custom_hash.size() < key_size {
				if !cfg.allow_smaller_size {
					return error('Hash into smaller size than current key size was not allowed')
				}
			}
			// we reset the custom hash before write
			cfg.custom_hash.reset()
			_ := cfg.custom_hash.write(msg)!
			msg_digest := cfg.custom_hash.sum([]u8{})
			// TODO: check if msg_digest was biggers than signature size
			out := sign_digest(pv.key, msg_digest)!

			return out
		}
	}
}

// PublicKey represents ECDSA public key.
pub struct PublicKey {
	key &C.EVP_PKEY
}

// free releases the memory occupied by this public key.
pub fn (pb &PublicKey) free() {
	C.EVP_PKEY_free(pb.key)
}

// verify verifies the signature whether this signature were a valid one for the message
// signed under the key and provided options. Its accepts options in opt to drive verify operation.
// As a note, verifying signature with options differs from the options used by the signing produces,
// would produce unmatching value (false).
// Dont forget to call `.free()` after you finish with the key.
pub fn (pb PublicKey) verify(signature []u8, msg []u8, opt SignerOpts) !bool {
	if msg.len == 0 {
		return error('Null-length message was not allowed')
	}
	bits_size := C.EVP_PKEY_get_bits(pb.key)
	if bits_size <= 0 {
		return error(' bits_size was invalid')
	}
	key_size := (bits_size + 7) / 8
	match opt.hash_config {
		.with_no_hash {
			if msg.len > key_size || msg.len > max_digest_size {
				return error('Unmatching msg size, use .with_default_hash options instead')
			}
			if msg.len < key_size {
				if !opt.allow_smaller_size {
					return error('Use allow_smaller_size explicitly')
				}
			}
			return verify_signature(pb.key, signature, msg)
		}
		.with_default_hash {
			ctx := C.EVP_MD_CTX_new()
			md := default_digest(pb.key)!
			init := C.EVP_DigestVerifyInit(ctx, 0, md, 0, pb.key)
			if init != 1 {
				C.EVP_MD_CTX_free(ctx)
				C.EVP_MD_free(md)
				return false
			}
			fin := C.EVP_DigestVerify(ctx, signature.data, signature.len, msg.data, msg.len)
			// cleans up
			C.EVP_MD_CTX_free(ctx)
			C.EVP_MD_free(md)

			return fin == 1
		}
		.with_custom_hash {
			mut cfg := opt
			if cfg.custom_hash.size() < key_size {
				if !cfg.allow_smaller_size {
					return error('Hash into smaller size than current key size was not allowed')
				}
			}
			cfg.custom_hash.reset()
			_ := cfg.custom_hash.write(msg)!
			msg_digest := cfg.custom_hash.sum([]u8{})

			return verify_signature(pb.key, signature, msg_digest)
		}
	}
}

// Helpers
//
// size returns the size of the key under the current NID curve.
// The curve key size was well-known infos. Its here for simplify the access.
fn (n Nid) size() int {
	match n {
		.prime256v1, .secp256k1 {
			return 32
		}
		.secp384r1 {
			return 48
		}
		.secp521r1 {
			// 521 bits was 66 bytes
			return 66
		}
	}
}

// return Nid as a string.
fn (nid Nid) str() string {
	return unsafe { nid.sn().vstring() }
}

// short name of this Nid as a &char
fn (nid Nid) sn() &char {
	match nid {
		.prime256v1 { return sn_prime256v1 }
		.secp384r1 { return sn_secp384r1 }
		.secp521r1 { return sn_secp521r1 }
		.secp256k1 { return sn_secp256k1 }
	}
}
