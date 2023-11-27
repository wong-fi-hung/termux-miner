enum algos {
	ALGO_KECCAK,      /* Keccak (old) */
	ALGO_KECCAKC,     /* Keccak */
	ALGO_HEAVY,       /* Heavy */
	ALGO_NEOSCRYPT,   /* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20 */
	ALGO_QUARK,       /* Quark */
	ALGO_ALLIUM,      /* Garlicoin double lyra2 */
	ALGO_ANIME,       /* Animecoin */
	ALGO_AXIOM,       /* Shabal 256 Memohash */
	ALGO_BASTION,
	ALGO_BLAKE,       /* Blake 256 */
	ALGO_BLAKECOIN,   /* Simplified 8 rounds Blake 256 */
	ALGO_BLAKE2B,
	ALGO_BLAKE2S,     /* Blake2s */
	ALGO_BMW,         /* BMW 256 */
	ALGO_BMW512,      /* BMW 512 [KONJ, XDN] */
	ALGO_C11,         /* C11 Chaincoin/Flaxcoin X11 variant */
	ALGO_CPUPOWER,    /* CPUchain */
	ALGO_CURVE,       /* Curve coin */
	ALGO_DECRED,      /* Decred */
	ALGO_DEDAL,       /* GlobalToken */
	ALGO_DMD_GR,      /* Diamond */
	ALGO_DROP,        /* Dropcoin */
	ALGO_FRESH,       /* Fresh */
	ALGO_GEEK,
	ALGO_GR,          /* Ghostrider */
	ALGO_GROESTL,     /* Groestl */
	ALGO_JHA,
	ALGO_LBRY,        /* Lbry Sha Ripemd */
	ALGO_LUFFA,       /* Luffa (Joincoin, Doom) */
	ALGO_LYRA2,       /* Lyra2RE */
	ALGO_LYRA2REV2,   /* Lyra2REv2 */
	ALGO_LYRA2V3,     /* Lyra2REv3 (Vertcoin) */
	ALGO_MEGABTX,     /* BitCore */
	ALGO_MEME,        /* PEPEW (PepePOW) */
	ALGO_MYR_GR,      /* Myriad Groestl */
	ALGO_MIKE,        /* Vkax */
	ALGO_MINOTAUR,    /* Ring */
	ALGO_MINOTAURX,   /* AVN, MAZA, LCC */
	ALGO_NIST5,       /* Nist5 */
	ALGO_PENTABLAKE,  /* Pentablake */
	ALGO_PHI1612,
	ALGO_PHI2,
	ALGO_PLUCK,       /* Pluck (Supcoin) */
	ALGO_POWER2B,     /* MBC (Microbit) */
	ALGO_QUBIT,       /* Qubit */
	ALGO_RAINFOREST,  /* RainForest */
	ALGO_SCRYPT,      /* scrypt */
	ALGO_SCRYPTJANE,  /* Chacha */
	ALGO_SHAVITE3,    /* Shavite3 */
	ALGO_SHA256D,     /* SHA-256d */
	ALGO_SIA,         /* Blake2-B */
	ALGO_SIB,         /* X11 + gost (Sibcoin) */
	ALGO_SKEIN,       /* Skein */
	ALGO_SKEIN2,      /* Double skein (Woodcoin) */
	ALGO_SKUNK,       /* GlobalToken */
	ALGO_SONOA,
	ALGO_S3,          /* S3 */
	ALGO_TIMETRAVEL,  /* Timetravel-8 (Machinecoin) */
	ALGO_BITCORE,     /* Timetravel-10 (Bitcore) */
	ALGO_TRIBUS,      /* Denarius jh/keccak/echo */
	ALGO_VANILLA,     /* Vanilla (Blake256 8-rounds - double sha256) */
	ALGO_VELTOR,      /* Skein Shavite Shabal Streebog */
	ALGO_X11EVO,      /* Permuted X11 */
	ALGO_X11,         /* X11 */
	ALGO_X12,
	ALGO_X13,         /* X13 */
	ALGO_X14,         /* X14 */
	ALGO_X15,         /* X15 */
	ALGO_X16R,        /* X16R */
	ALGO_X16RV2,      /* X16Rv2 */
	ALGO_X16S,
	ALGO_X17,         /* X17 */
	ALGO_0X10,        /* 0x10 (Chain0x [CHOX])*/
	ALGO_X20R,
	ALGO_XEVAN,
	ALGO_YESCRYPT,
	ALGO_YESCRYPTR8,
	ALGO_YESCRYPTR16, /* GOLD (Goldcash) */
	ALGO_YESCRYPTR32, /* DMS (Document) */
	ALGO_YESPOWER,    /* CRP, Veco */
	ALGO_YESPOWERR16, /* YTN (Yenten) */
	ALGO_YESPOWERIC,  /* ISO (IsotopeC) */
	ALGO_YESPOWERIOTS,/* Yespower based algo for IOTS */
	ALGO_YESPOWERITC, /* ITC (Intercoin) */
	ALGO_YESPOWERLITB,/* LITB (LightBit) */
	ALGO_YESPOWERLNC, /* LNC (LigtningCash) */
	ALGO_YESPOWER_MGPC, /*yespowerMGPC (Magpiecoin) */
	ALGO_YESPOWERSUGAR, /* SUGAR (Sugarchain) */
	ALGO_YESPOWERTIDE, /* TDC (Tidecoin) */
	ALGO_YESPOWERURX, /* URX (UraniumX) */
	ALGO_ZR5,
	ALGO_COUNT
};

static const char *algo_names[] = {
	"keccak",
	"keccakc",
	"heavy",
	"neoscrypt",
	"quark",
	"allium",
	"anime",
	"axiom",
	"bastion",
	"blake",
	"blakecoin",
	"blake2b",
	"blake2s",
	"bmw",
	"bmw512",
	"c11",
	"cpupower",
	"curve",
	"decred",
	"dedal",
	"dmd-gr",
	"drop",
	"fresh",
	"geek",
	"gr",
	"groestl",
	"jha",
	"lbry",
	"luffa",
	"lyra2re",
	"lyra2rev2",
	"lyra2v3",
	"megabtx",
	"meme",
	"myr-gr",
	"mike",
	"minotaur",
	"minotaurx",
	"nist5",
	"pentablake",
	"phi1612",
	"phi2",
	"pluck",
	"power2b",
	"qubit",
	"rainforest",
	"scrypt",
	"scrypt-jane",
	"shavite3",
	"sha256d",
	"sia",
	"sib",
	"skein",
	"skein2",
	"skunk",
	"sonoa",
	"s3",
	"timetravel",
	"bitcore",
	"tribus",
	"vanilla",
	"veltor",
	"x11evo",
	"x11",
	"x12",
	"x13",
	"x14",
	"x15",
	"x16r",
	"x16rv2",
	"x16s",
	"x17",
	"0x10",
	"x20r",
	"xevan",
	"yescrypt",
	"yescryptR8",
	"yescryptR16",
	"yescryptR32",
	"yespower",
	"yespowerR16",
	"yespowerIC",
	"yespowerIOTS",
	"yespowerITC",
	"yespowerLITB",
	"yespowerLNC",
	"yespowerMGPC",
	"yespowerSUGAR",
	"yespowerTIDE",
	"yespowerURX",
	"zr5",
	"\0"
};
