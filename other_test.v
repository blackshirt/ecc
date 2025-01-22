module xecc

fn test_key_dump() ! {
	key := PrivateKey.new(curve: 'secp384r1')!
	// dump(key.dump_key())

	pb := key.public_key()!
	dump(pb.dump_key())
	pb.info()
}

fn test_load_privkey_from_bytes() ! {
	pvkey := load_privkey_from_bytes()!

	dump(pvkey.dump_key())
	msg := 'MessageTobeSigned'.bytes()
	signature := pvkey.sign(msg)!

	pbkey := pvkey.public_key()!
	assert pbkey.verify(signature, msg)! == true
}
