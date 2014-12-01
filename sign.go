package bitauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/conformal/btcec"
	"github.com/conformal/btcwire"
)

// Returns a hex encoded signature for the given data and private key.
// Note that the private key must be a hex-encoded byte slice.
func Sign(data, private string) (string, error) {
	pkBytes, err := hex.DecodeString(private)
	if err != nil {
		return "", err
	}
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)

	dataHash := btcwire.DoubleSha256([]byte(data))
	signature, err := privKey.Sign(dataHash)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(signature.Serialize()), nil
}

// @TODO: Implement custom signature verification from Bitauth
func VerifySignature(data, sign, public string) (bool, error) {
	// Decode hex-encoded serialized public key.
	pubKeyBytes, err := hex.DecodeString(public)
	if err != nil {
		return false, err
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	if err != nil {
		return false, err
	}

	// Decode hex-encoded serialized signature.
	sigBytes, err := hex.DecodeString(sign)
	if err != nil {
		return false, err
	}
	signature, err := btcec.ParseSignature(sigBytes, btcec.S256())
	if err != nil {
		return false, err
	}

	dataHash := btcwire.DoubleSha256([]byte(data))

	return signature.Verify(dataHash, pubKey), nil
}

// Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
// This is a port of Bitcore's Key.rs2DER method.
func PointsToDER(r, s *big.Int) []byte {
	// Ensure MSB doesn't break big endian encoding in DER sigs
	prefixPoint := func(b []byte) []byte {
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			paddedBytes := make([]byte, len(b)+1)
			copy(paddedBytes[1:], b)
			b = paddedBytes
		}
		return b
	}

	rb := prefixPoint(r.Bytes())
	sb := prefixPoint(s.Bytes())

	// DER encoding:
	// 0x30 + z + 0x02 + len(rb) + rb + 0x02 + len(sb) + sb
	length := 2 + len(rb) + 2 + len(sb)

	der := append([]byte{0x30, byte(length), 0x02, byte(len(rb))}, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)

	encoded := make([]byte, hex.EncodedLen(len(der)))
	hex.Encode(encoded, der)

	return encoded
}

// Create a signature from a hash and private key using a random nonce generated via crypto/rand
func sign(priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	random := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return
	}
	return signDeterministically(priv, hash, random)
}

// Create a signature determinstailly from a given random byte array
// @TODO: Replace with Golang's built in ecdsa.Verify method using a new Reader for random
func signDeterministically(priv *ecdsa.PrivateKey, hash, random []byte) (r, s *big.Int, err error) {
	// Generate a new random byte array if necessary
	if len(random) != 32 {
		random = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, random)
	}

	e := new(big.Int).SetBytes(hash)
	k := new(big.Int).SetBytes(random)
	d := priv.D

	secp256k1 := priv.Curve.Params()

	// Calculate R
	Gx, Gy := secp256k1.Gx, secp256k1.Gy
	Qx, _ := priv.Curve.ScalarMult(Gx, Gy, k.Bytes())
	r = Qx.Mod(Qx, secp256k1.N)

	// Calclulate S
	k.ModInverse(k, secp256k1.N)
	d.Mul(priv.D, r)
	e.Add(e, d)
	k.Mul(k, e)
	s = k.Mod(k, secp256k1.N)

	return
}