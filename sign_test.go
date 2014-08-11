package bitauth

import (
	"testing"
)

// @TODO: Test using external/deterministic signatures to verify signing works as expected
func TestSign(t *testing.T) {
	privKey := []byte("1217a587403374c5b21897bda9eaaa88f7315c931e4cb1d40f24fcf8f4d34419")
	pubKey := []byte("023f5d74e874b2f7c784729fc93b7d38a3c28129d27321b2e4f7cde09d7609adff")

	data := [][]byte{
		[]byte("test"),
		[]byte("{foo:\"bar\"}"),
	}

	for i := range data {
		signed := Sign(data[i], privKey)
		if !VerifySignature(data[i], signed, pubKey) {
			t.Errorf("Invalid signature generated")
		}
	}

}
