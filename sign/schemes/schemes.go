// Package schemes contains a register of signature algorithms.
//
// Implemented schemes:
//
//	Ed25519
//	Ed448
//	Ed25519-Dilithium3
//	Ed448-Dilithium4
package schemes

import (
	"github.com/navaneethrameshan/circl/sign/dilithiumhighsign"
	"strings"

	"github.com/navaneethrameshan/circl/sign"
	"github.com/navaneethrameshan/circl/sign/ed25519"
	"github.com/navaneethrameshan/circl/sign/ed448"
	"github.com/navaneethrameshan/circl/sign/eddilithium3"
	"github.com/navaneethrameshan/circl/sign/eddilithium4"
)

var allSchemes = [...]sign.Scheme{
	ed25519.Scheme(),
	ed448.Scheme(),
	eddilithium3.Scheme(),
	eddilithium4.Scheme(),
	dilithiumhighsign.Scheme(),
}

var allSchemeNames map[string]sign.Scheme

func init() {
	allSchemeNames = make(map[string]sign.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the scheme with the given name and nil if it is not
// supported.
//
// Names are case insensitive.
func ByName(name string) sign.Scheme {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all signature schemes supported.
func All() []sign.Scheme { a := allSchemes; return a[:] }
