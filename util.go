package bitauth

import (
	"crypto/sha256"
	"encoding/hex"
)

func sum256AsByte(data []byte) []byte {
	checksum := sha256.Sum256(data)
	return checksum[:32]
}

// Helper utility to decode a hex-encoded public or private key
func decodeHex(data []byte) []byte {
	var decoded = make([]byte, hex.DecodedLen(len(data)))
	hex.Decode(decoded, data)
	return decoded
}

// Hex encodes a sha256 hash of given data
func encodeHex(data []byte) []byte {
	var byt = make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(byt, data)
	return byt
}
