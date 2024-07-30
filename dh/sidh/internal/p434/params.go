package p434

//go:generate go run ../templates/gen.go P434

import (
	"github.com/navaneethrameshan/circl/dh/sidh/internal/common"
	"golang.org/x/sys/cpu"
)

const (
	// Number of uint64 limbs used to store field element
	FpWords = 7
)

var (
	// HasADXandBMI2 signals support for ADX and BMI2
	HasADXandBMI2 = cpu.X86.HasBMI2 && cpu.X86.HasADX

	// P434 is a prime used by field Fp434
	P434 = common.Fp{
		0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFDC1767AE2FFFFFF,
		0x7BC65C783158AEA3, 0x6CFC5FD681C52056, 0x2341F27177344,
	}

	// P434x2 = 2*p434 - 1
	P434x2 = common.Fp{
		0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFB82ECF5C5FFFFFF,
		0xF78CB8F062B15D47, 0xD9F8BFAD038A40AC, 0x4683E4E2EE688,
	}

	// P434p1 = p434 + 1
	P434p1 = common.Fp{
		0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xFDC1767AE3000000,
		0x7BC65C783158AEA3, 0x6CFC5FD681C52056, 0x0002341F27177344,
	}

	// P434R2 = (2^448)^2 mod p
	P434R2 = common.Fp{
		0x28E55B65DCD69B30, 0xACEC7367768798C2, 0xAB27973F8311688D, 0x175CC6AF8D6C7C0B,
		0xABCD92BF2DDE347E, 0x69E16A61C7686D9A, 0x000025A89BCDD12A,
	}

	// 1/2 * R mod p
	half = common.Fp2{
		A: common.Fp{
			0x0000000000003A16, 0x0000000000000000, 0x0000000000000000, 0x5C87FA027E000000,
			0x6C00D27DAACFD66A, 0x74992A2A2FBBA086, 0x0000767753DE976D},
	}

	// 1*R mod p
	one = common.Fp2{
		A: common.Fp{
			0x000000000000742C, 0x0000000000000000, 0x0000000000000000, 0xB90FF404FC000000,
			0xD801A4FB559FACD4, 0xE93254545F77410C, 0x0000ECEEA7BD2EDA},
	}

	// 6*R mod p
	six = common.Fp2{
		A: common.Fp{
			0x000000000002B90A, 0x0000000000000000, 0x0000000000000000, 0x5ADCCB2822000000,
			0x187D24F39F0CAFB4, 0x9D353A4D394145A0, 0x00012559A0403298},
	}

	P434p1Zeros = 3

	params = common.SidhParams{
		ID: common.Fp434,
		// SIDH public key byte size.
		PublicKeySize: 330,
		// SIDH shared secret byte size.
		SharedSecretSize: 110,
		InitCurve: common.ProjectiveCurveParameters{
			A: six,
			C: one,
		},
		A: common.DomainParams{
			// The x-coordinate of PA
			AffineP: common.Fp2{
				A: common.Fp{
					0x05ADF455C5C345BF, 0x91935C5CC767AC2B, 0xAFE4E879951F0257, 0x70E792DC89FA27B1,
					0xF797F526BB48C8CD, 0x2181DB6131AF621F, 0x00000A1C08B1ECC4,
				},
				B: common.Fp{
					0x74840EB87CDA7788, 0x2971AA0ECF9F9D0B, 0xCB5732BDF41715D5, 0x8CD8E51F7AACFFAA,
					0xA7F424730D7E419F, 0xD671EB919A179E8C, 0x0000FFA26C5A924A,
				},
			},
			// The x-coordinate of QA
			AffineQ: common.Fp2{
				A: common.Fp{
					0xFEC6E64588B7273B, 0xD2A626D74CBBF1C6, 0xF8F58F07A78098C7, 0xE23941F470841B03,
					0x1B63EDA2045538DD, 0x735CFEB0FFD49215, 0x0001C4CB77542876,
				},
				B: common.Fp{
					0xADB0F733C17FFDD6, 0x6AFFBD037DA0A050, 0x680EC43DB144E02F, 0x1E2E5D5FF524E374,
					0xE2DDA115260E2995, 0xA6E4B552E2EDE508, 0x00018ECCDDF4B53E,
				},
			},

			// The x-coordinate of RA = PA-QA
			AffineR: common.Fp2{
				A: common.Fp{
					0x01BA4DB518CD6C7D, 0x2CB0251FE3CC0611, 0x259B0C6949A9121B, 0x60E17AC16D2F82AD,
					0x3AA41F1CE175D92D, 0x413FBE6A9B9BC4F3, 0x00022A81D8D55643,
				},
				B: common.Fp{
					0xB8ADBC70FC82E54A, 0xEF9CDDB0D5FADDED, 0x5820C734C80096A0, 0x7799994BAA96E0E4,
					0x044961599E379AF8, 0xDB2B94FBF09F27E2, 0x0000B87FC716C0C6,
				},
			},
			// Max size of secret key for 2-torsion group, corresponds to 2^e2 - 1
			SecretBitLen: 216,
			// SecretBitLen in bytes.
			SecretByteLen: 28,
			// 2-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x30, 0x1C, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01,
				0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04,
				0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x0D, 0x07, 0x04, 0x02, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x05, 0x04,
				0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01,
				0x15, 0x0C, 0x07, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x03, 0x02, 0x01, 0x01, 0x01, 0x01, 0x05, 0x03, 0x02, 0x01,
				0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x09, 0x05, 0x03,
				0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01, 0x04,
				0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01},
		},
		B: common.DomainParams{
			// The x-coordinate of PB
			AffineP: common.Fp2{
				A: common.Fp{
					0x6E5497556EDD48A3, 0x2A61B501546F1C05, 0xEB919446D049887D, 0x5864A4A69D450C4F,
					0xB883F276A6490D2B, 0x22CC287022D5F5B9, 0x0001BED4772E551F,
				},
				B: common.Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of QB
			AffineQ: common.Fp2{
				A: common.Fp{
					0xFAE2A3F93D8B6B8E, 0x494871F51700FE1C, 0xEF1A94228413C27C, 0x498FF4A4AF60BD62,
					0xB00AD2A708267E8A, 0xF4328294E017837F, 0x000034080181D8AE,
				},
				B: common.Fp{
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
					0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
				},
			},
			// The x-coordinate of RB = PB - QB
			AffineR: common.Fp2{
				A: common.Fp{
					0x283B34FAFEFDC8E4, 0x9208F44977C3E647, 0x7DEAE962816F4E9A, 0x68A2BA8AA262EC9D,
					0x8176F112EA43F45B, 0x02106D022634F504, 0x00007E8A50F02E37,
				},
				B: common.Fp{
					0xB378B7C1DA22CCB1, 0x6D089C99AD1D9230, 0xEBE15711813E2369, 0x2B35A68239D48A53,
					0x445F6FD138407C93, 0xBEF93B29A3F6B54B, 0x000173FA910377D3,
				},
			},
			// Size of secret key for 3-torsion group, corresponds to log_2(3^e3) - 1.
			SecretBitLen: 217,
			// SecretBitLen in bytes.
			SecretByteLen: 28,
			// 3-torsion group computation strategy
			IsogenyStrategy: []uint32{
				0x42, 0x21, 0x11, 0x09, 0x05, 0x03, 0x02, 0x01, 0x01, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02,
				0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x10,
				0x08, 0x04, 0x02, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04,
				0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01,
				0x01, 0x20, 0x10, 0x08, 0x04, 0x03, 0x01, 0x01, 0x01, 0x01,
				0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
				0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04, 0x02,
				0x01, 0x01, 0x02, 0x01, 0x01, 0x10, 0x08, 0x04, 0x02, 0x01,
				0x01, 0x02, 0x01, 0x01, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01,
				0x01, 0x08, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x04,
				0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
		},
		OneFp2:  one,
		HalfFp2: half,
		MsgLen:  16,
		// SIKEp434 provides 192 bit of classical security ([SIKE], 5.1)
		KemSize: 16,
		// ceil(434+7/8)
		Bytelen:        55,
		CiphertextSize: 16 + 330,
	}
)

func init() {
	common.Register(common.Fp434, &params)
}
