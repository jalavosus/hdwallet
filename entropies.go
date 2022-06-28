package hdwallet

const (
	// Entropy128Bit is the minimum entropy amount allowed by BIP39,
	// and results in a BIP39 mnemonic of length 12.
	Entropy128Bit int = 128
	// Entropy160Bit results in a BIP39 mnemonic of length 15.
	Entropy160Bit int = 160
	// Entropy192Bit results in a BIP39 mnemonic of length 18.
	Entropy192Bit int = 192
	// Entropy224Bit results in a BIP39 mnemonic of length 21.
	Entropy224Bit int = 224
	// Entropy256Bit is the maximum entropy amount allowed by BIP39,
	// and results in a BIP39 mnemonic of length 24.
	Entropy256Bit int = 256
)
