package p503

//go:generate go run ../templates/gen.go P503

import (
	"github.com/navaneethrameshan/circl/dh/sidh/internal/common"
	"golang.org/x/sys/cpu"
)

const (
	// Number of uint64 limbs used to store field element
	FpWords = 8
)

// P503 is a prime used by field Fp503
var (
	// According to https://github.com/golang/go/issues/28230,
	// variables referred from the assembly must be in the same package.
	// HasBMI2 signals support for MULX which is in BMI2
	HasBMI2 = cpu.X86.HasBMI2
	// HasADXandBMI2 signals support for ADX and BMI2
	HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX

	// P503 is a prime used by field Fp503
	P503 = common.Fp{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xABFFFFFFFFFFFFFF,
		0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E,
	}

	// P503x2 = 2*p503 - 1
	P503x2 = common.Fp{
		0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x57FFFFFFFFFFFFFF,
		0x2610B7B44423CF41, 0x3737ED90F6FCFB5E, 0xC08B8D7BB4EF49A0, 0x0080CDEA83023C3C,
	}

	// P503p1 = p503 + 1
	P503p1 = common.Fp{
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xAC00000000000000,
		0x13085BDA2211E7A0, 0x1B9BF6C87B7E7DAF, 0x6045C6BDDA77A4D0, 0x004066F541811E1E,
	}

	// P503R2 = (2^512)^2 mod p
	P503R2 = common.Fp{
		0x5289A0CF641D011F, 0x9B88257189FED2B9, 0xA3B365D58DC8F17A, 0x5BC57AB6EFF168EC,
		0x9E51998BD84D4423, 0xBF8999CBAC3B5695, 0x46E9127BCE14CDB6, 0x003F6CFCE8B81771,
	}

	// P503p1s8 = p503 + 1 left-shifted by 8, assuming little endianness
	P503p1s8 = common.Fp{
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
		0x085BDA2211E7A0AC, 0x9BF6C87B7E7DAF13, 0x45C6BDDA77A4D01B, 0x4066F541811E1E60,
	}

	// P503p1Zeros number of 0 digits in the least significant part of P503+1
	P503p1Zeros = 3

	// 1*R mod p
	one = common.Fp2{
		A: common.Fp{
			0x00000000000003F9, 0x0000000000000000, 0x0000000000000000, 0xB400000000000000,
			0x63CB1A6EA6DED2B4, 0x51689D8D667EB37D, 0x8ACD77C71AB24142, 0x0026FBAEC60F5953,
		},
	}
	// 1/2 * R mod p
	half = common.Fp2{
		A: common.Fp{
			0x00000000000001FC, 0x0000000000000000, 0x0000000000000000, 0xB000000000000000,
			0x3B69BB2464785D2A, 0x36824A2AF0FE9896, 0xF5899F427A94F309, 0x0033B15203C83BB8,
		},
	}
	// 6*R mod p
	six = common.Fp2{
		A: common.Fp{
			0x00000000000017D8, 0x0000000000000000, 0x0000000000000000, 0xE000000000000000,
			0x30B1E6E3A51520FA, 0xB13BC3BF6FFB3992, 0x8045412EEB3E3DED, 0x0069182E2159DBB8,
		},
	}

	params = common.SidhParams{
		ID: common.Fp503,
		// SIDH public key byte size.
		PublicKeySize: 378,
		// SIDH shared secret byte size.
		SharedSecretSize: 126,
		A: common.DomainParams{
			// The x-coordinate of PA
			AffineP: common.Fp2{
				A: common.Fp{
					0x5D083011589AD893, 0xADFD8D2CB67D0637, 0x330C9AC34FFB6361, 0xF0D47489A2E805A2,
					0x27E2789259C6B8DC, 0x63866A2C121931B9, 0x8D4C65A7137DCF44, 0x003A183AE5967B3F,
				},
				B: common.Fp{
					0x7E3541B8C96D1519, 0xD3ADAEEC0D61A26C, 0xC0A2219CE7703DD9, 0xFF3E46658FCDBC52,
					0xD5B38DEAE6E196FF, 0x1AAC826364956D58, 0xEC9F4875B9A5F27A, 0x001B0B475AB99843,
				},
			},
			// The x-coordinate of QA
			AffineQ: common.Fp2{
				A: common.Fp{
					0x4D83695107D03BAD, 0x221F3299005E2FCF, 0x78E6AE22F30DECF2, 0x6D982DB5111253E4,
					0x504C80A8AB4526A8, 0xEFD0C3AA210BB024, 0xCB77483501DC6FCF, 0x001052544A96BDF3,
				},
				B: common.Fp{
					0x0D74FE3402BCAE47, 0xDF5B8CDA832D8AED, 0xB86BCF06E4BD837E, 0x892A2933A0FA1F63,
					0x9F88FC67B6CCB461, 0x822926EA9DDA3AC8, 0xEAC8DDE5855425ED, 0x000618FE6DA37A80,
				},
			},

			// The x-coordinate of RA = PA-QA
			AffineR: common.Fp2{
				A: common.Fp{
					0x1D9D32D2DC877C17, 0x5517CD8F71D5B02B, 0x395AFB8F6B60C117, 0x3AE31AC85F9098C8,
					0x5F5341C198450848, 0xF8C609DBEA435C6A, 0xD832BC7EDC7BA5E4, 0x002AD98AA6968BF5,
				},
				B: common.Fp{
					0xC466CAB0F73C2E5B, 0x7B1817148FB2CF9C, 0x873E87C099E470A0, 0xBB17AC6D17A7BAC1,
					0xA146FDCD0F2E2A58, 0x88B311E9CEAB6201, 0x37604CF5C7951757, 0x0006804071C74BF9,
				},
			},
			// Max size of secret key for 2-torsion group, corresponds to 2^e2 - 1
			SecretBitLen: 250,
			// SecretBitLen in bytes.
			SecretByteLen: 32,
			// 2-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x3D, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01,
				0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x1D, 0x10, 0x08, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x0D, 0x08,
				0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x05, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
			},
		},
		B: common.DomainParams{
			// The x-coordinate of PB
			AffineP: common.Fp2{
				A: common.Fp{
					0xDF630FC5FB2468DB, 0xC30C5541C102040E, 0x3CDC9987B76511FC, 0xF54B5A09353D0CDD,
					0x3ADBA8E00703C42F, 0x8253F9303DDC95D0, 0x62D30778763ABFD7, 0x001CD00FB581CD55,
				},
				B: common.Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of QB
			AffineQ: common.Fp2{
				A: common.Fp{
					0x2E3457A12B429261, 0x311F94E89627DCF8, 0x5B71C98FD1DB73F6, 0x3671DB7DCFC21541,
					0xB6D1484C9FE0CF4F, 0x19CD110717356E35, 0xF4F9FB00AC9919DF, 0x0035BC124D38A70B,
				},
				B: common.Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of RB = PB - QB
			AffineR: common.Fp2{
				A: common.Fp{
					0x2E08BB99413D2952, 0xD3021467CD088D72, 0x21017AF859752245, 0x26314ED8FFD9DE5C,
					0x4AF43C73344B6686, 0xCFA1F91149DF0993, 0xF327A95365587A89, 0x000DBF54E03D3906,
				},
				B: common.Fp{
					0x03E03FF342F5F304, 0x993D604D7B4B6E56, 0x80412F4D9280E71F, 0x0FFDC9EF990B3982,
					0xE584E64C51604931, 0x1374F42AC8B0BBD7, 0x07D5BC37DFA41A5F, 0x00396CCFD61FD34C,
				},
			},
			// Size of secret key for 3-torsion group, corresponds to log_2(3^e3) - 1.
			SecretBitLen: 252,
			// SecretBitLen in bytes.
			SecretByteLen: 32,
			// 3-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x47, 0x26, 0x15, 0x0D, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x05, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x01, 0x09, 0x05, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x11, 0x09, 0x05, 0x03, 0x02,
				0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x21, 0x11, 0x09, 0x05, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04,
				0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01,
			},
		},
		OneFp2:  one,
		HalfFp2: half,
		MsgLen:  24,
		// SIKEp503 provides 192 bit of classical security ([SIKE], 5.1)
		KemSize: 24,
		// ceil(503+7/8)
		Bytelen:        63,
		CiphertextSize: 24 + 378,
		InitCurve: common.ProjectiveCurveParameters{
			A: six,
			C: one,
		},
	}
)

func init() {
	common.Register(common.Fp503, &params)
}
