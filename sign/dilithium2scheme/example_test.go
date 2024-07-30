package dilithium2scheme_test

import (
	"fmt"
	"github.com/navaneethrameshan/circl/sign/dilithium2scheme"
)

func Example() {
	// Generates a keypair.
	pk, sk, err := dilithium2scheme.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// (Alternatively one can derive a keypair from a seed,
	// see NewKeyFromSeed().)

	// Packs public and private key
	var packedSk [dilithium2scheme.PrivateKeySize]byte
	var packedPk [dilithium2scheme.PublicKeySize]byte
	sk.Pack(&packedSk)
	pk.Pack(&packedPk)

	// Load it again
	var sk2 dilithium2scheme.PrivateKey
	var pk2 dilithium2scheme.PublicKey
	sk2.Unpack(&packedSk)
	pk2.Unpack(&packedPk)

	// Creates a signature on our message with the generated private key.
	msg := []byte("Some message")
	var signature [dilithium2scheme.SignatureSize]byte
	dilithium2scheme.SignTo(&sk2, msg, signature[:])

	// Checks whether a signature is correct
	if !dilithium2scheme.Verify(&pk2, msg, signature[:]) {
		panic("incorrect signature")
	}

	fmt.Printf("O.K.")

	// Output:
	// O.K.
}
