module xecc

fn test_sign_veriyf_without_hash() ! {
	pv := PrivateKey.new()!
	msg := 'a'.repeat(245).bytes()
	sign := sign_message(pv.key, msg)!

	pb := pv.public_key()!
	verifieda := verify_signature(pb.key, sign, msg)
	assert verifieda

	msgb := 'a'.repeat(71).bytes()
	verifiedb := verify_signature(pb.key, sign, msgb)
	dump(verifiedb)

	msgc := 'a'.repeat(56).bytes()
	verifiedc := verify_signature(pb.key, sign, msgc)
	dump(verifiedc)

	msgd := 'a'.repeat(300).bytes()
	verifiedd := verify_signature(pb.key, sign, msgd)
	dump(verifiedd)

	msge := 'd'.repeat(71).bytes()
	verifiede := verify_signature(pb.key, sign, msge)
	dump(verifiede)
}
