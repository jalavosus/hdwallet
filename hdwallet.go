package hdwallet

import (
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/pkg/errors"
)

// HDWallet represents a BIP32/BIP44 Hierarchical Deterministic Wallet.
type HDWallet struct {
	masterKey   *hdkeychain.ExtendedKey
	seed        []byte
	entropy     []byte
	mnemonic    []string
	entropyBits int
	account     *walletAccount
	initOnce    *sync.Once
	opts        *walletOpts
}

func newEmptyHDWallet(opts ...NewWalletOpt) *HDWallet {
	w := &HDWallet{
		initOnce: new(sync.Once),
		opts:     defaultWalletOpts(),
	}

	for _, o := range opts {
		o.apply(w.opts)
	}

	return w
}

// NewHDWallet constructs and returns an *HDWallet instance
// using any passed NewWalletOpt parameters.
func NewHDWallet(opts ...NewWalletOpt) (*HDWallet, error) {
	return newEmptyHDWallet(opts...).init()
}

func (w *HDWallet) init() (*HDWallet, error) {
	var initErr error

	w.initOnce.Do(func() {
		bip39Data, err := makeBIP39Data(w.opts)

		if err != nil {
			initErr = errors.Wrap(err, "error generating bip39 data")
			return
		}

		keychain, err := hdkeychain.NewMaster(bip39Data.Seed, &chaincfg.MainNetParams)
		if err != nil {
			initErr = errors.Wrap(err, "error creating master Extended Key")
			return
		}

		if bip39Data.Seed != nil {
			w.seed = bip39Data.Seed
		}
		if bip39Data.Entropy != nil {
			w.entropy = bip39Data.Entropy
		}

		w.masterKey = keychain
		w.mnemonic = strings.Split(bip39Data.Mnemonic, " ")
		w.entropyBits = w.opts.entropyBits

		w.account = newWalletAccount(w.masterKey, 0, w.opts.newKeyForAccount)

		w.opts = nil
	})

	if initErr != nil {
		return nil, initErr
	}

	return w, nil
}

// DeriveAddress derives a new, non-hardened child account using the next available
// derivation index.
// If the next available derivation index is the start of available "hardened"
// derivation indices, an error is returned.
func (w *HDWallet) DeriveAddress() (*HDWalletAddress, error) {
	if w.account.lastNonHardenedIdx == hdkeychain.HardenedKeyStart {
		return nil, errors.New("maximum number of non-hardened accounts created")
	}

	fancyDerived, err := w.account.derive(w.account.lastNonHardenedIdx)
	if err != nil {
		return nil, err
	}

	w.account.lastNonHardenedIdx++

	return fancyDerived, nil
}

// DeriveHardenedAddress derives a new, hardened child account using the next available
// derivation index.
func (w *HDWallet) DeriveHardenedAddress() (*HDWalletAddress, error) {
	newDerivationIdx := w.account.lastHardenedIdx + 1
	if newDerivationIdx == 0xFFFFFFFF {
		return nil, errors.New("maximum number of hardened accounts created")
	}

	fancyDerived, err := w.account.derive(newDerivationIdx)
	if err != nil {
		return nil, err
	}

	w.account.lastHardenedIdx = newDerivationIdx

	return fancyDerived, nil
}

// DeriveAddressFromIndex derives a new child account using the provided derivation
// index, which can be a hardened or non-hardened index.
func (w *HDWallet) DeriveAddressFromIndex(idx int) (*HDWalletAddress, error) {
	fancyDerived, err := w.account.derive(idx)
	if err != nil {
		return nil, err
	}

	return fancyDerived, nil
}

func (w HDWallet) MasterKey() *hdkeychain.ExtendedKey {
	return w.masterKey
}

func (w HDWallet) Mnemonic() string {
	return strings.Join(w.mnemonic, " ")
}

func (w HDWallet) Seed() []byte {
	return w.seed
}

func (w HDWallet) Entropy() []byte {
	return w.entropy
}

func (w HDWallet) Accounts() []*HDWalletAddress {
	return w.account.derivedAddrs
}
