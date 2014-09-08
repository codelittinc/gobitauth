package bitauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/sour-is/koblitz/kelliptic"
)

// Returns a hex encoded signature for the given data and private key.
// Note that the private key must be a hex-encoded byte slice.
func Sign(data, privKey []byte) (signed []byte) {
	D := new(big.Int)
	D.SetString(string(privKey), 16)

	c := kelliptic.S256()
	priv := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: c,
		},
		D: D,
	}

	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(D.Bytes())

	digest := encodeHex(sum256AsByte(data))

	if len(digest) != 64 {
		return
	}

	// @TODO: Use RFC 6979 to generate deterministic nonces ensuring they will
	//        never repeat.
	r, s, err := sign(&priv, digest)
	if err != nil {
		panic(err.Error())
	}

	return PointsToDER(r, s)
}

// @TODO: Calculate signature verification based on bitauth/bitcore's signature verification code. Apparently,
//        the build-in ecdsa signature algorith in golang doesn't work
// func VerifySignature(data, signature, pubKeyByt []byte) bool {
// 	// Hex decode public key
// 	pubKeyByt = decodeHex(pubKeyByt)
//
// 	// Decompress the public key on the 265k1 graph, which returns the pubkey's
// 	// X and Y points
// 	c := kelliptic.S256()
// 	x, y, err := c.DecompressPoint(pubKeyByt)
// 	if err != nil {
// 		return false
// 	}
//
// 	pub := ecdsa.PublicKey{
// 		Curve: c,
// 		X:     x,
// 		Y:     y,
// 	}
//
// 	// A signature is a DES encoded string of two points (R and S) on the secp256k1 graph
// 	// We need to unmarshal the signature and retrieve the R/S points to verify.
// 	R, S := PointsFromDER(decodeHex(signature))
//
// 	return ecdsa.Verify(&pub, encodeHex(sum256AsByte(data)), R, S)
// }

// Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
// This is a port of Bitcore's Key.rs2DER method.
func PointsToDER(r, s *big.Int) []byte {
	// Is either point negative? If so, we need to prepend 0x00 before each elem.
	rb := r.Bytes()
	sb := s.Bytes()

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

// Get the X and Y points from a DER encoded signature
// Sometimes demarshalling using Golang's DEC to struct unmarshalling fails; this extracts R and S from the bytes
// manually to prevent crashing.
// This should NOT be a hex encoded byte array
func PointsFromDER(der []byte) (R, S *big.Int) {
	// @TODO: Detect DER hex encoding and fail (or decode) if it's hex encoded
	R, S = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	if _, err := asn1.Unmarshal(der, &data); err != nil {
		panic(err.Error())
	}

	// The format of our DER string is 0x02 + rlen + r + 0x02 + slen + s
	rLen := data.Bytes[1] // The entire length of R + offset of 2 for 0x02 and rlen
	r := data.Bytes[2 : rLen+2]
	// Ignore the next 0x02 and slen bytes and just take the start of S to the end of the byte array
	s := data.Bytes[rLen+4:]

	R.SetBytes(r)
	S.SetBytes(s)

	return
}

// Create a signature from a hash and private key using a random nonce generated via crypto/rand
func sign(priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	random := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return
	}
	return signDeterministically(priv, hash, random)
}


// Implement the algo from Bitauth to verify signatures. This is a different algorithm
// to Golang's ecdsa.Sign method.
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
	k.Mul(k, e.Add(e, d.Mul(priv.D, r)))
	s = k.Mod(k, secp256k1.N)

	return
}
