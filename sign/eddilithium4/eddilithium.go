// Package eddilithium4 implements the hybrid signature scheme Ed448-Dilithium4.
package eddilithium4

import (
	"crypto"
	cryptoRand "crypto/rand"
	"errors"
	"io"

	"github.com/navaneethrameshan/circl/internal/sha3"
	"github.com/navaneethrameshan/circl/sign"
	"github.com/navaneethrameshan/circl/sign/dilithium/mode4"
	"github.com/navaneethrameshan/circl/sign/ed448"
)

const (
	// SeedSize is the length of the seed for NewKeyFromSeed
	SeedSize = ed448.SeedSize // > mode4.SeedSize

	// PublicKeySize is the length in bytes of the packed public key.
	PublicKeySize = mode4.PublicKeySize + ed448.PublicKeySize

	// PrivateKeySize is the length in bytes of the packed public key.
	PrivateKeySize = mode4.PrivateKeySize + ed448.SeedSize

	// SignatureSize is the length in bytes of the signatures.
	SignatureSize = mode4.SignatureSize + ed448.SignatureSize
)

// PublicKey is the type of an EdDilithium4 public key.
type PublicKey struct {
	e ed448.PublicKey
	d mode4.PublicKey
}

// PrivateKey is the type of an EdDilithium4 private key.
type PrivateKey struct {
	e ed448.PrivateKey
	d mode4.PrivateKey
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [SeedSize]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}

	pk, sk := NewKeyFromSeed(&seed)
	return pk, sk, nil
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	var seed1 [32]byte
	var seed2 [ed448.SeedSize]byte

	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Read(seed1[:])
	_, _ = h.Read(seed2[:])
	dpk, dsk := mode4.NewKeyFromSeed(&seed1)
	esk := ed448.NewKeyFromSeed(seed2[:])

	return &PublicKey{esk.Public().(ed448.PublicKey), *dpk}, &PrivateKey{esk, *dsk}
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	mode4.SignTo(
		&sk.d,
		msg,
		signature[:mode4.SignatureSize],
	)
	esig := ed448.Sign(
		sk.e,
		msg,
		"",
	)
	copy(signature[mode4.SignatureSize:], esig[:])
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	if !mode4.Verify(
		&pk.d,
		msg,
		signature[:mode4.SignatureSize],
	) {
		return false
	}
	if !ed448.Verify(
		pk.e,
		msg,
		signature[mode4.SignatureSize:],
		"",
	) {
		return false
	}
	return true
}

// Unpack unpacks pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	var tmp [mode4.PublicKeySize]byte
	copy(tmp[:], buf[:mode4.PublicKeySize])
	pk.d.Unpack(&tmp)
	pk.e = make([]byte, ed448.PublicKeySize)
	copy(pk.e, buf[mode4.PublicKeySize:])
}

// Unpack sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	var tmp [mode4.PrivateKeySize]byte
	copy(tmp[:], buf[:mode4.PrivateKeySize])
	sk.d.Unpack(&tmp)
	sk.e = ed448.NewKeyFromSeed(buf[mode4.PrivateKeySize:])
}

// Pack packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	var tmp [mode4.PublicKeySize]byte
	pk.d.Pack(&tmp)
	copy(buf[:mode4.PublicKeySize], tmp[:])
	copy(buf[mode4.PublicKeySize:], pk.e)
}

// Pack packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	var tmp [mode4.PrivateKeySize]byte
	sk.d.Pack(&tmp)
	copy(buf[:mode4.PrivateKeySize], tmp[:])
	copy(buf[mode4.PrivateKeySize:], sk.e.Seed())
}

// Bytes packs the public key.
func (pk *PublicKey) Bytes() []byte {
	return append(pk.d.Bytes(), pk.e...)
}

// Bytes packs the private key.
func (sk *PrivateKey) Bytes() []byte {
	return append(sk.d.Bytes(), sk.e.Seed()...)
}

// MarshalBinary packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// MarshalBinary packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// UnmarshalBinary the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of eddilithium4.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// UnmarshalBinary unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of eddilithium4.PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}

func (sk *PrivateKey) Scheme() sign.Scheme { return sch }
func (pk *PublicKey) Scheme() sign.Scheme  { return sch }

func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return castOther.e.Equal(sk.e) && castOther.d.Equal(&sk.d)
}

func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return castOther.e.Equal(pk.e) && castOther.d.Equal(&pk.d)
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	signature []byte, err error) {
	var sig [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("eddilithium4: cannot sign hashed message")
	}

	SignTo(sk, msg, sig[:])
	return sig[:], nil
}

// Public computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{
		sk.e.Public().(ed448.PublicKey),
		*sk.d.Public().(*mode4.PublicKey),
	}
}
