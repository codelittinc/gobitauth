package bitauth

import (
	"encoding/hex"
	"math/big"
	"testing"
)

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
			t.Fatalf("Invalid zero-length of signed data for %s", data[i])
		}
		if !VerifySignature(data[i], signed, pubKey) {
			t.Errorf("Invalid signature generated")
		}
	}

}

type KeyRS struct {
	DER string
	R   string // Base 16 encoded number
	S   string
}

func TestPointsFromDER(t *testing.T) {
	data := []KeyRS{
		KeyRS{
			DER: "3045022078611477d7824bc8e48a4aa242e8b7733ef0315e2127682533e175a371df6447022100f91beab703e13cf3622d5140af8ec341cc994bb23a98021acb260d0959f47ed2",
			R:   "78611477d7824bc8e48a4aa242e8b7733ef0315e2127682533e175a371df6447",
			S:   "00f91beab703e13cf3622d5140af8ec341cc994bb23a98021acb260d0959f47ed2",
		},
		KeyRS{
			DER: "3046022100aebe330b80993d10c8f6dd54787f458c18c5df438898f514efac3d6c51172af2022100e5fe2c1bb2156708f2ec3389a16e1308219e67e7ba2dd04653634c69f2b36e98",
			R:   "00aebe330b80993d10c8f6dd54787f458c18c5df438898f514efac3d6c51172af2",
			S:   "00e5fe2c1bb2156708f2ec3389a16e1308219e67e7ba2dd04653634c69f2b36e98",
		},
	}

	for i := range data {
		var r, s big.Int
		R, _ := r.SetString(data[i].R, 16)
		S, _ := s.SetString(data[i].S, 16)

		der, _ := hex.DecodeString(data[i].DER)
		gotR, gotS := PointsFromDER(der)

		if gotR.Cmp(R) != 0 || gotS.Cmp(S) != 0 {
			t.Fatalf("Unexpected R/S from DER string.\nExpected %v, %v\nGot %v, %v", R, S, gotR, gotS)
		}
	}
}
