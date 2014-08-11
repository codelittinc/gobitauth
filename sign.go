package bitauth

import (
	secp256k1 "github.com/haltingstate/secp256k1-go"

	"encoding/hex"
)

// Returns a hex encoded signature for the given data and private key.
// Note that the private key must be a hex-encoded byte slice.
func Sign(data, privKey []byte) (signed []byte) {
	var decoded = make([]byte, hex.DecodedLen(len(privKey)))
	hex.Decode(decoded, privKey)

	return secp256k1.Sign(data, decoded)
}

func VerifySignature(data, signature, pubKey []byte) bool {
	// @TODO: Abstract Key type and add decode/encode methods
	var decoded = make([]byte, hex.DecodedLen(len(pubKey)))
	hex.Decode(decoded, pubKey)

	if secp256k1.VerifySignature(data, signature, decoded) == 1 {
		return true
	} else {
		return false
	}
}
