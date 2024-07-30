// Code generated by go generate; DO NOT EDIT.
// This file was generated by robots.

package p434

import (
	"bytes"
	"testing"

	. "github.com/navaneethrameshan/circl/dh/sidh/internal/common"
)

func vartimeEqProjFp2(lhs, rhs *ProjectivePoint) bool {
	var t0, t1 Fp2
	mul(&t0, &lhs.X, &rhs.Z)
	mul(&t1, &lhs.Z, &rhs.X)
	return vartimeEqFp2(&t0, &t1)
}

func toAffine(point *ProjectivePoint) *Fp2 {
	var affineX Fp2
	inv(&affineX, &point.Z)
	mul(&affineX, &affineX, &point.X)
	return &affineX
}

func Test_jInvariant(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curveA, C: curveC}
	var jbufRes = make([]byte, params.SharedSecretSize)
	var jbufExp = make([]byte, params.SharedSecretSize)
	var jInv Fp2

	Jinvariant(&curve, &jInv)
	FromMontgomery(&jInv, &jInv)
	Fp2ToBytes(jbufRes, &jInv, params.Bytelen)

	jInv = expectedJ
	FromMontgomery(&jInv, &jInv)
	Fp2ToBytes(jbufExp, &jInv, params.Bytelen)

	if !bytes.Equal(jbufRes[:], jbufExp[:]) {
		t.Error("Computed incorrect j-invariant: found\n", jbufRes, "\nexpected\n", jbufExp)
	}
}

func TestProjectivePointVartimeEq(t *testing.T) {
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affineXP, Z: params.OneFp2}
	xQ := xP

	// Scale xQ, which results in the same projective point
	mul(&xQ.X, &xQ.X, &curveA)
	mul(&xQ.Z, &xQ.Z, &curveA)
	if !vartimeEqProjFp2(&xP, &xQ) {
		t.Error("Expected the scaled point to be equal to the original")
	}
}

func TestPointMulVersusSage(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curveA, C: curveC}
	var cparams = CalcCurveParamsEquiv4(&curve)
	var xP ProjectivePoint

	// x 2
	xP = ProjectivePoint{X: affineXP, Z: params.OneFp2}
	Pow2k(&xP, &cparams, 1)
	afxQ := toAffine(&xP)
	if !vartimeEqFp2(afxQ, &affineXP2) {
		t.Error("\nExpected\n", affineXP2, "\nfound\n", afxQ)
	}

	// x 4
	xP = ProjectivePoint{X: affineXP, Z: params.OneFp2}
	Pow2k(&xP, &cparams, 2)
	afxQ = toAffine(&xP)
	if !vartimeEqFp2(afxQ, &affineXP4) {
		t.Error("\nExpected\n", affineXP4, "\nfound\n", afxQ)
	}
}

func TestPointMul9VersusSage(t *testing.T) {
	var curve = ProjectiveCurveParameters{A: curveA, C: curveC}
	var cparams = CalcCurveParamsEquiv3(&curve)
	var xP ProjectivePoint

	xP = ProjectivePoint{X: affineXP, Z: params.OneFp2}
	Pow3k(&xP, &cparams, 2)
	afxQ := toAffine(&xP)
	if !vartimeEqFp2(afxQ, &affineXP9) {
		t.Error("\nExpected\n", affineXP9, "\nfound\n", afxQ)
	}
}

func BenchmarkThreePointLadder(b *testing.B) {
	var curve = ProjectiveCurveParameters{A: curveA, C: curveC}
	for n := 0; n < b.N; n++ {
		ScalarMul3Pt(&curve, &threePointLadderInputs[0], &threePointLadderInputs[1], &threePointLadderInputs[2], uint(len(scalar3Pt)*8), scalar3Pt[:])
	}
}
