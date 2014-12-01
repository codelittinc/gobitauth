package bitauth

import (
	"code.google.com/p/go.crypto/ripemd160"
	"github.com/conformal/btcec"
	"github.com/tonyhb/base58check"

	"encoding/hex"
	"math/big"
	"strings"
)

// Get a public key's SIN as specified in
// https://en.bitcoin.it/wiki/Identity_protocol_v1#Creating_a_SIN
func GetSINFromPublicKeyString(key string) (sin SIN, err error) {
	var decoded []byte
	if decoded, err = hex.DecodeString(key); err != nil {
		return
	}
	return GetSINFromPublicKey(decoded), nil
}

func GetSINFromPublicKey(key []byte) (sin SIN) {
	var ripe = ripemd160.New()

	// Get ripemd160(sha256(key))
	ripe.Write(sum256AsByte(key))
	hash160 := ripe.Sum(make([]byte, 0))

	// Prefix 0x0F 0x02 to hash160; 0x02 refers to the SIN type (ephemeral)
	prefixed := append([]byte{0x0F, 0x02}, hash160...)

	// Double-sha256 of the prefixed hash160
	sha := sum256AsByte(sum256AsByte(prefixed))

	// Get the first 4 hex bytes of double-sha string and append them to the hex-encoded prefix hash160
	var hexencoded = make([]byte, hex.EncodedLen(len(sha)))
	hex.Encode(hexencoded, sha)

	step6 := strings.Join([]string{hex.EncodeToString(prefixed), string(hexencoded[0:8])}, "")

	i := new(big.Int)
	i.SetString(step6, 16)

	return SIN(string(base58.EncodeBig([]byte{}, i)))
}

// Get a public key from any private key
func GetPublicKeyFromPrivateKeyString(private string) (pubkey []byte, err error) {
	var decoded []byte
	if decoded, err = hex.DecodeString(private); err != nil {
		return
	}
	return GetPublicKeyFromPrivateKey(decoded), nil
}

func GetPublicKeyFromPrivateKey(private []byte) (pubkey []byte) {
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), []byte(private))

	return encodeHex(pubKey.SerializeCompressed())
}

// This uses an external library (github.com/haltingstate/secp256k1-go) which
// delegates to Bitcoin's secp256k1 C library when generating SINs. Its
// randommness isn't guaranteed. Use with caution.
func GenerateSIN() (*SINInfo, error) {
	// Generate key public/private key pair
	prvKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}

	pubKey := prvKey.PubKey().SerializeCompressed()

	sin := GetSINFromPublicKey(pubKey)

	return &SINInfo{
		PrivateKey: prvKey.Serialize(),
		PublicKey:  pubKey,
		SIN:        sin,
	}, nil
}

type SIN []byte

// Holds a pub/prv keypair and a SIN byte slice
type SINInfo struct {
	SIN        SIN
	PublicKey  []byte
	PrivateKey []byte
}

func (t SINInfo) EncodedPublicKey() string {
	return hex.EncodeToString(t.PublicKey)
}

func (t SINInfo) EncodedPrivateKey() string {
	return hex.EncodeToString(t.PrivateKey)
}
