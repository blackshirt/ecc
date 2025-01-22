module xecc

fn test_load_keys() ! {
	key := load_key_from_bytes()!
	pvkey := PrivateKey{
		key: key
	}
	msg := 'MessageTobeSigned'.bytes()
	signature := pvkey.sign(msg)!

	pbkey := pvkey.public_key()!
	assert pbkey.verify(signature, msg)! == true
	dump(pbkey.dump_key())

	output := pvkey.dump_key()
	dump(output)
	pvkey.info()
}
