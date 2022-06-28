package hdwallet

type walletOpts struct {
	passphrase       string
	entropyBits      int
	mnemonic         string
	entropy          []byte
	newKeyForAccount bool
}

type funcWalletOpt struct {
	f func(*walletOpts)
}

func newFuncWalletOpt(f func(*walletOpts)) *funcWalletOpt {
	return &funcWalletOpt{f}
}

func (fo *funcWalletOpt) apply(opts *walletOpts) {
	fo.f(opts)
}

type NewWalletOpt interface {
	apply(*walletOpts)
}

func WithPassphrase(passphrase string) NewWalletOpt {
	return newFuncWalletOpt(func(opts *walletOpts) {
		opts.passphrase = passphrase
	})
}

func WithEntropyBits(entropyBits int) NewWalletOpt {
	return newFuncWalletOpt(func(opts *walletOpts) {
		opts.entropyBits = entropyBits
	})
}

func WithMnemonic(mnemonic string) NewWalletOpt {
	return newFuncWalletOpt(func(opts *walletOpts) {
		opts.mnemonic = mnemonic
	})
}

func WithEntropy(entropy []byte) NewWalletOpt {
	return newFuncWalletOpt(func(opts *walletOpts) {
		opts.entropy = entropy
	})
}

func WithDeriveKeyForAccount(newKey bool) NewWalletOpt {
	return newFuncWalletOpt(func(opts *walletOpts) {
		opts.newKeyForAccount = newKey
	})
}

func defaultWalletOpts() *walletOpts {
	return &walletOpts{
		entropyBits: Entropy256Bit,
	}
}
