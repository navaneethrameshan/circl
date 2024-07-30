package p751

//go:generate go run ../templates/gen.go P751

import (
	"github.com/navaneethrameshan/circl/dh/sidh/internal/common"
	"golang.org/x/sys/cpu"
)

const (
	// Number of uint64 limbs used to store field element
	FpWords = 12
)

var (
	// HasBMI2 signals support for MULX which is in BMI2
	HasBMI2 = cpu.X86.HasBMI2
	// HasADXandBMI2 signals support for ADX and BMI2
	HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX
	// P751 is a prime used by field Fp751
	P751 = common.Fp{
		0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
		0xffffffffffffffff, 0xffffffffffffffff, 0xeeafffffffffffff,
		0xe3ec968549f878a8, 0xda959b1a13f7cc76, 0x084e9867d6ebe876,
		0x8562b5045cb25748, 0x0e12909f97badc66, 0x00006fe5d541f71c,
	}

	// P751x2 = 2*p751 - 1
	P751x2 = common.Fp{
		0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xDD5FFFFFFFFFFFFF,
		0xC7D92D0A93F0F151, 0xB52B363427EF98ED, 0x109D30CFADD7D0ED,
		0x0AC56A08B964AE90, 0x1C25213F2F75B8CD, 0x0000DFCBAA83EE38,
	}

	// P751p1 = p751 + 1
	P751p1 = common.Fp{
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x0000000000000000, 0x0000000000000000, 0xeeb0000000000000,
		0xe3ec968549f878a8, 0xda959b1a13f7cc76, 0x084e9867d6ebe876,
		0x8562b5045cb25748, 0x0e12909f97badc66, 0x00006fe5d541f71c,
	}

	// P751R2 = (2^768)^2 mod p
	P751R2 = common.Fp{
		0x233046449DAD4058, 0xDB010161A696452A, 0x5E36941472E3FD8E,
		0xF40BFE2082A2E706, 0x4932CCA8904F8751, 0x1F735F1F1EE7FC81,
		0xA24F4D80C1048E18, 0xB56C383CCDB607C5, 0x441DD47B735F9C90,
		0x5673ED2C6A6AC82A, 0x06C905261132294B, 0x000041AD830F1F35,
	}

	// P751p1Zeros number of 0 digits in the least significant part of P751+1
	P751p1Zeros = 5

	// 1*R mod p
	one = common.Fp2{
		A: common.Fp{
			0x00000000000249ad, 0x0000000000000000, 0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x8310000000000000,
			0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e,
			0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x00002d5b24bce5e2,
		},
	}
	// 1/2 * R mod p
	half = common.Fp2{
		A: common.Fp{
			0x00000000000124D6, 0x0000000000000000, 0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0xB8E0000000000000,
			0x9C8A2434C0AA7287, 0xA206996CA9A378A3, 0x6876280D41A41B52,
			0xE903B49F175CE04F, 0x0F8511860666D227, 0x00004EA07CFF6E7F,
		},
	}
	// 6*R mod p
	six = common.Fp2{
		A: common.Fp{
			0x00000000000DBA10, 0x0000000000000000, 0x0000000000000000,
			0x0000000000000000, 0x0000000000000000, 0x3500000000000000,
			0x3714FE4EB8399915, 0xC3A2584753EB43F4, 0xA3151D605C520428,
			0xC116CF5232C7C978, 0x49A84D4B8EFAF6AA, 0x0000305731E97514,
		},
	}

	params = common.SidhParams{
		ID: common.Fp751,
		// SIDH public key byte size.
		PublicKeySize: 564,
		// SIDH shared secret byte size.
		SharedSecretSize: 188,
		A: common.DomainParams{
			// The x-coordinate of PA
			AffineP: common.Fp2{
				A: common.Fp{
					0x884F46B74000BAA8, 0xBA52630F939DEC20, 0xC16FB97BA714A04D,
					0x082536745B1AB3DB, 0x1117157F446F9E82, 0xD2F27D621A018490,
					0x6B24AB523D544BCD, 0x9307D6AA2EA85C94, 0xE1A096729528F20F,
					0x896446F868F3255C, 0x2401D996B1BFF8A5, 0x00000EF8786A5C0A,
				},
				B: common.Fp{
					0xAEB78B3B96F59394, 0xAB26681E29C90B74, 0xE520AC30FDC4ACF1,
					0x870AAAE3A4B8111B, 0xF875BDB738D64EFF, 0x50109A7ECD7ED6BC,
					0x4CC64848FF0C56FB, 0xE617CB6C519102C9, 0x9C74B3835921E609,
					0xC91DDAE4A35A7146, 0x7FC82A155C1B9129, 0x0000214FA6B980B3,
				},
			},
			// The x-coordinate of QA
			AffineQ: common.Fp2{
				A: common.Fp{
					0x0F93CC38680A8CA9, 0x762E733822E7FED7, 0xE549F005AC0ADB67,
					0x94A71FDD2C43A4ED, 0xD48645C2B04721C5, 0x432DA1FE4D4CA4DC,
					0xBC99655FAA7A80E8, 0xB2C6D502BCFD4823, 0xEE92F40CA2EC8BDB,
					0x7B074132EFB6D16C, 0x3340B46FA38A7633, 0x0000215749657F6C,
				},
				B: common.Fp{
					0xECFF375BF3079F4C, 0xFBFE74B043E80EF3, 0x17376CBE3C5C7AD1,
					0xC06327A7E29CDBF2, 0x2111649C438BF3D4, 0xC1F9298261BA2E97,
					0x1F9FECE869CFD1C2, 0x01A39B4FC9346D62, 0x147CD1D3E82A3C9F,
					0xDE84E9D249E533EE, 0x1C48A5ADFB7C578D, 0x000061ACA0B82E1D,
				},
			},
			// The x-coordinate of RA = PA-QA
			AffineR: common.Fp2{
				A: common.Fp{
					0x1600C525D41059F1, 0xA596899A0A1D83F7, 0x6BFDEED6D2B23F35,
					0x5C7E707270C23910, 0x276CA1A4E8369411, 0xB193651A602925A0,
					0x243D239F1CA1F04A, 0x543DC6DA457860AD, 0xCDA590F325181DE9,
					0xD3AB7ACFDA80B395, 0x6C97468580FDDF7B, 0x0000352A3E5C4C77,
				},
				B: common.Fp{
					0x9B794F9FD1CC3EE8, 0xDB32E40A9B2FD23E, 0x26192A2542E42B67,
					0xA18E94FCA045BCE7, 0x96DC1BC38E7CDA2D, 0x9A1D91B752487DE2,
					0xCC63763987436DA3, 0x1316717AACCC551D, 0xC4C368A4632AFE72,
					0x4B6EA85C9CCD5710, 0x7A12CAD582C7BC9A, 0x00001C7E240149BF,
				},
			},
			// Max size of secret key for 2-torsion group, corresponds to 2^e2 - 1
			SecretBitLen: 372,
			// SecretBitLen in bytes.
			SecretByteLen: 47,
			// 2-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x50, 0x30, 0x1B, 0x0F, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x07,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03, 0x02, 0x01,
				0x01, 0x01, 0x01, 0x0C, 0x07, 0x04, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x05, 0x03,
				0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x15,
				0x0C, 0x07, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03,
				0x02, 0x01, 0x01, 0x01, 0x01, 0x05, 0x03, 0x02, 0x01, 0x01,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x09, 0x05, 0x03, 0x02,
				0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x21, 0x14, 0x0C, 0x07,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03, 0x02, 0x01,
				0x01, 0x01, 0x01, 0x05, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x01, 0x08, 0x05, 0x03, 0x02, 0x01, 0x01,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01,
			},
		},
		B: common.DomainParams{
			// The x-coordinate of PB
			AffineP: common.Fp2{
				A: common.Fp{
					0x85691AAF4015F88C, 0x7478C5B8C36E9631, 0x7EF2A185DE4DD6E2,
					0x943BBEE46BEB9DC7, 0x1A3EC62798792D22, 0x791BC4B084B31D69,
					0x03DBE6522CEA17C4, 0x04749AA65D665D83, 0x3D52B5C45EF450F3,
					0x0B4219848E36947D, 0xA4CF7070466BDE27, 0x0000334B1FA6D193,
				},
				B: common.Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of QB
			AffineQ: common.Fp2{
				A: common.Fp{
					0x8E7CB3FA53211340, 0xD67CE54F7A05EEE0, 0xFDDC2C8BCE46FC38,
					0x08587FAE3110DF1E, 0xD6B8246FA22B058B, 0x4DAC3ACC905A5DBD,
					0x51D0BF2FADCED3E8, 0xE5A2406DF6484425, 0x907F177584F671B8,
					0x4738A2FFCCED051C, 0x2B0067B4177E4853, 0x00002806AC948D3D,
				},
				B: common.Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of RB = PB - QB
			AffineR: common.Fp2{
				A: common.Fp{
					0xB56457016D1D6D1C, 0x03DECCB38F39C491, 0xDFB910AC8A559452,
					0xA9D0F17D1FF24883, 0x8562BBAF515C248C, 0x249B2A6DDB1CB67D,
					0x3131AF96FB46835C, 0xE10258398480C3E1, 0xEAB5E2B872D4FAB1,
					0xB71E63875FAEB1DF, 0xF8384D4F13757CF6, 0x0000361EC9B09912,
				},
				B: common.Fp{
					0x58C967899ED16EF4, 0x81998376DC622A4B, 0x3D1C1DCFE0B12681,
					0x9347DEBB953E1730, 0x9ABB344D3A82C2D7, 0xE4881BD2820552B2,
					0x0037247923D90266, 0x2E3156EDB157E5A5, 0xF86A46A7506823F7,
					0x8FE5523A7B7F1CFC, 0xFA3CFFA38372F67B, 0x0000692DCE85FFBD,
				},
			},
			// Size of secret key for 3-torsion group, corresponds to log_2(3^e3) - 1.
			SecretBitLen: 378,
			// SecretBitLen in bytes.
			SecretByteLen: 48,
			// 3-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x70, 0x3F, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x1F, 0x10, 0x08, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x0F, 0x08, 0x04,
				0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x07, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01,
				0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x31, 0x1F, 0x10,
				0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x0F, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04,
				0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x07, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01,
				0x15, 0x0C, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x05, 0x03, 0x02,
				0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x09, 0x05,
				0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
				0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01,
			},
		},
		OneFp2:  one,
		HalfFp2: half,

		MsgLen: 32,
		// SIKEp751 provides 128 bit of classical security ([SIKE], 5.1)
		KemSize: 32,
		// ceil(751+7/8)
		Bytelen:        94,
		CiphertextSize: 32 + 564,
		InitCurve: common.ProjectiveCurveParameters{
			A: six,
			C: one,
		},
	}
)

func init() {
	common.Register(common.Fp751, &params)
}
