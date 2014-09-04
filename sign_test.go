package bitauth

import "testing"

// @TODO: Test using external/deterministic signatures to verify signing works as expected
func TestSign(t *testing.T) {
	privKey := []byte("1217a587403374c5b21897bda9eaaa88f7315c931e4cb1d40f24fcf8f4d34419")
	pubKey := []byte("023f5d74e874b2f7c784729fc93b7d38a3c28129d27321b2e4f7cde09d7609adff")

	data := [][]byte{
		[]byte("test"),
		[]byte("{foo:\"bar\"}"),
		[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec mauris magna, maximus eget ipsum et, congue faucibus risus. Phasellus sit amet felis rutrum, semper enim in, maximus eros. Nunc sodales rutrum mi, vel scelerisque lectus aliquam vel."),
	}

	for i := range data {
		signed := Sign(data[i], privKey)
		if len(signed) == 0 {
			t.Fatalf("Invalid zero-length of signed data")
		}
		if !VerifySignature(data[i], signed, pubKey) {
			t.Errorf("Invalid signature generated")
		}
	}

}
