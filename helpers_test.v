// Copyright (c) blackshirt. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module ecc

import crypto.sha1
import crypto.sha512

fn test_key_sign_verify_internal_function() ! {
	pv := PrivateKey.new(nid: .secp384r1)!
	msg := 'a'.repeat(20).bytes()
	digest := sha512.sum512(msg)
	sign := sign_digest(pv.key, digest)!

	pb := pv.public_key()!
	verifieda := verify_signature(pb.key, sign, digest)
	assert verifieda == true

	msgb := 'a'.repeat(71).bytes()
	digestb := sha512.sum512(msgb)
	verifiedb := verify_signature(pb.key, sign, digestb)
	assert verifiedb == false

	msgc := 'a'.repeat(12).bytes()
	digestc := sha1.sum(msgc)
	verifiedc := verify_signature(pb.key, sign, digestc)
	assert verifiedc == false

	msgd := 'a'.repeat(300).bytes()
	verifiedd := verify_signature(pb.key, sign, msgd)
	assert verifiedd == false

	msge := 'd'.repeat(71).bytes()
	verifiede := verify_signature(pb.key, sign, msge)
	assert verifiede == false
	pv.free()
	pb.free()
}

fn test_key_sign_n_verify_signature() ! {
	pkey := PrivateKey.new()!
	pbkey := pkey.public_key()!
	msg := 'MessageTobeSigned'.bytes()

	sign_without_hashed := sign_digest(pkey.key, msg)!
	assert verify_signature(pbkey.key, sign_without_hashed, msg) == true

	sign_nohash := pkey.sign(msg, hash_config: .with_no_hash, allow_smaller_size: true)!
	assert pbkey.verify(sign_nohash, msg, hash_config: .with_no_hash, allow_smaller_size: true)! == true
	assert verify_signature(pbkey.key, sign_nohash, msg) == true

	pkey.free()
	pbkey.free()
}
