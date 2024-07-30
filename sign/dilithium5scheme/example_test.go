package dilithium5scheme_test

import (
	"fmt"
	"github.com/navaneethrameshan/circl/sign/dilithium5scheme"
)

func Example() {
	// Generates a keypair.
	pk, sk, err := dilithium5scheme.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// (Alternatively one can derive a keypair from a seed,
	// see NewKeyFromSeed().)

	// Packs public and private key
	var packedSk [dilithium5scheme.PrivateKeySize]byte
	var packedPk [dilithium5scheme.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)

	// Load it again
	var sk2 dilithium5scheme.PrivateKey
	var pk2 dilithium5scheme.PublicKey
	sk2.Unpack(&packedSk)
	pk2.Unpack(&packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	var signature [dilithium5scheme.SignatureSize]byte
	dilithium5scheme.SignTo(&sk2, msg, signature[:])

	// Checks whether a signature is correct
	if !dilithium5scheme.Verify(&pk2, msg, signature[:]) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// O.K.
}
