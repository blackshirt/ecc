// Copyright @blackshirt 2025
//
import x.crypto.xecc

fn main() {
	// creates a new default key
	pvkey := xecc.PrivateKey.new()!
	// Message to be signed
	msg := 'Example of the new ecdsa module'.bytes()
	// create a signature for the message based on the generated key.
	signature := pvkey.sign(msg)!

	// gets the public key to verify signature
	pbkey := pvkey.public_key()!
	// checks validity of the signature for message.
	valid := pbkey.verify(signature, msg)!
	if valid {
		println('Valid signature')
	} else {
		println('Invalid signature')
	}

	// cleanups the keys
	pvkey.free()
	pbkey.free()
}
