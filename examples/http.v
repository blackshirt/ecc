import net.http
import ecc

fn main() {
	resp := http.get('https://url4e.com/unknown')!
	dump(resp.body)

	pvkey := ecc.PrivateKey.new()!
	signature := pvkey.sign(resp.body.bytes())!

	pubkey := pvkey.public_key()!
	verified := pubkey.verify(signature, resp.body.bytes())!
	dump(verified)
}
