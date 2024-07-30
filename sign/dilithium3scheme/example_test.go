package dilithium3scheme_test

import (
	"fmt"
	"github.com/navaneethrameshan/circl/sign/dilithium3scheme"
)

func Example() {
	// Generates a keypair.
	pk, sk, err := dilithium3scheme.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// (Alternatively one can derive a keypair from a seed,
	// see NewKeyFromSeed().)

	// Packs public and private key
	var packedSk [dilithium3scheme.PrivateKeySize]byte
	var packedPk [dilithium3scheme.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)

	// Load it again
	var sk2 dilithium3scheme.PrivateKey
	var pk2 dilithium3scheme.PublicKey
	sk2.Unpack(&packedSk)
	pk2.Unpack(&packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	var signature [dilithium3scheme.SignatureSize]byte
	dilithium3scheme.SignTo(&sk2, msg, signature[:])

	// Checks whether a signature is correct
	if !dilithium3scheme.Verify(&pk2, msg, signature[:]) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// O.K.
}
