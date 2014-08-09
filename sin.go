package bitauth

import (
	"code.google.com/p/go.crypto/ripemd160"
	"github.com/tonyhb/base58"

	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

type SIN []byte

type SINInfo struct {
	SIN        SIN
	PublicKey  []byte
	PrivateKey []byte
}

func GetSINFromPublicKey(key string) (sin SIN, err error) {
	var decoded []byte
	var ripe = ripemd160.New()

	if decoded, err = hex.DecodeString(key); err != nil {
		return
	}

	// Get ripemd160(sha256(key))
	ripe.Write(sum256AsByte(decoded))
	hash160 := ripe.Sum(make([]byte, 0))

	// Prefix 0x0F 0x02 to hash160; 0x02 refers to the SIN type (ephemeral)
	prefixed := joinBytes([]byte{0x0F, 0x02}, hash160)

	// Double-sha256 of the prefixed hash160
	sha := sum256AsByte(sum256AsByte(prefixed))

	// Get the first 4 hex bytes of double-sha string and append them to the hex-encoded prefix hash160
	var hexencoded = make([]byte, hex.EncodedLen(len(sha)))
	hex.Encode(hexencoded, sha)

	step6 := strings.Join([]string{hex.EncodeToString(prefixed), string(hexencoded[0:8])}, "")

	i := new(big.Int)
	i.SetString(step6, 16)

	return SIN(string(base58.EncodeBig([]byte{}, i))), nil
}

func GenerateSIN() (SINInfo, error) {
	return SINInfo{}, nil
}

func GetPublicKeyFromPrivateKey(private []byte) ([]byte, error) {
	return []byte{}, nil
}

func sum256AsByte(data []byte) []byte {
	checksum := sha256.Sum256(data)
	return checksum[:32]
}

func joinBytes(a, b []byte) []byte {
	return bytes.Join([][]byte{a, b}, []byte{})
}
