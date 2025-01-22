module xecc

fn test_key_dump() ! {
	key := PrivateKey.new()!
	//dump(key.dump_key())
	
	pb := key.public_key()!
	pb.info()
}

/*
fn test_load_privkey_from_bytes() ! {
	key := load_privkey_from_bytes()!
	pvkey := PrivateKey{
		key: key
	}
	pvkey.info()
	msg := 'MessageTobeSigned'.bytes()
	signature := pvkey.sign(msg)!

	pbkey := pvkey.public_key()!
	assert pbkey.verify(signature, msg)! == true
	dump(pbkey.dump_key())

	output := pvkey.dump_key()
	dump(output)
	pvkey.info()

	otk := pvkey.copy_params()!
	dump(otk.dump_params())
}
*/