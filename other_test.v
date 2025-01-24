module xecc

fn test_key_dump() ! {
	pkey := PrivateKey.new(nid: .secp384r1)!
	pkey.info()!
	dump(pkey.dump_key())
	b := pkey.bytes()!

	// creates pvkey back with bytes b
	p2 := PrivateKey.from_bytes(b, nid: .secp384r1)!
	p2.info()!
	dump(p2.dump_key())
	dump(p2.bytes()!.hex())
	assert p2.bytes()! == b

	p3 := pkey.public_key()!
	dump(p3.dump_key())
	p3.info()!
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
