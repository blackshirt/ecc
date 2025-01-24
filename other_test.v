module xecc

fn test_key_dump() ! {
	pkey := PrivateKey.new()!
	dump(pkey.dump_key())
	// pkey.info()
	b := pkey.bytes()!
	p2 := PrivateKey.from_bytes(b)!
	dump(p2.bytes()!.hex())
	dump(p2.bytes()!.len)
	pb := pkey.public_key()!
	dump(pb.bytes()!.hex())
	// assert C.EVP_PKEY_get_ec_point_conv_form(pkey.key) == point_conversion_compressed
	// dump(pb.dump_key())
	// pb.info()
}

/*
fn test_load_privkey_from_bytes() ! {
	pvkey := PrivateKey.from_bytes()!

	dump(pvkey.dump_key())
	msg := 'MessageTobeSigned'.bytes()
	signature := pvkey.sign(msg)!

	pbkey := pvkey.public_key()!
	assert pbkey.verify(signature, msg)! == true
}
*/
