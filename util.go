package hdwallet

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
)

type newBIP39Data struct {
	Mnemonic string
	Entropy  []byte
	Seed     []byte
}

type rawDerived struct {
	Address common.Address
	PrivKey *ecdsa.PrivateKey
	PubKey  ecdsa.PublicKey
}

const baseDerivationPath string = "m/44'/60'/%[1]d'/0/"

func isHardenedIdx(idx int) bool {
	return idx >= hdkeychain.HardenedKeyStart
}

func getHardenedIdx(idx int) int {
	return idx - hdkeychain.HardenedKeyStart
}

func addressDerivationPathFromIdx(accountIdx, addressIdx int) accounts.DerivationPath {
	var suffix string

	if isHardenedIdx(addressIdx) {
		addressIdx = getHardenedIdx(addressIdx)
		suffix = "'"
	}

	newPath := fmt.Sprintf(baseDerivationPath, accountIdx) + fmt.Sprintf("%[1]d%[2]s", addressIdx, suffix)

	p, err := accounts.ParseDerivationPath(newPath)
	if err != nil {
		panic(err)
	}

	return p
}

func makeBIP39DataFromMnemonic(entropy []byte, mnemonic, passphrase string) (*newBIP39Data, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, errors.Wrap(err, "error generating seed")
	}

	return &newBIP39Data{
		Mnemonic: mnemonic,
		Seed:     seed,
		Entropy:  entropy,
	}, nil
}

// EntropyFromString returns the []byte representation
// of a hex-encoded entropy string.
func EntropyFromString(entropy string) []byte {
	entropy = strings.TrimPrefix(entropy, "0x")

	e, _ := hex.DecodeString(entropy)

	return e
}

func makeBIP39Data(opts *walletOpts) (*newBIP39Data, error) {
	rand.Seed(time.Now().UnixNano())

	var (
		err      error
		entropy  []byte
		mnemonic string
	)

	if opts.entropy != nil {
		mnemonic, err = bip39.NewMnemonic(opts.entropy)
		if err != nil {
			return nil, err
		}

		return makeBIP39DataFromMnemonic(opts.entropy, mnemonic, opts.passphrase)
	} else {
		entropy, err = bip39.NewEntropy(opts.entropyBits)
		if err != nil {
			return nil, errors.Wrap(err, "error generating entropy")
		}
	}

	if opts.mnemonic != "" {
		mnemonic = opts.mnemonic
	} else {
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, errors.Wrap(err, "error generating mnemonic")
		}
	}

	return makeBIP39DataFromMnemonic(entropy, mnemonic, opts.passphrase)
}

func deriveNewAdressFromAccountKey(accountKey *hdkeychain.ExtendedKey, accountIdx, addressIdx int) (*rawDerived, error) {
	var (
		derivedKey = accountKey
		err        error
	)

	path := addressDerivationPathFromIdx(accountIdx, addressIdx)

	for _, n := range path {
		if derivedKey.IsAffectedByIssue172() {
			derivedKey, err = derivedKey.Derive(n)
		} else {
			derivedKey, err = derivedKey.DeriveNonStandard(n)
		}

		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, errors.Wrap(err, "error creating child Extended Key")
	}

	privKeyRaw, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, err
	}

	privKey := privKeyRaw.ToECDSA()
	pubKey := privKey.Public().(*ecdsa.PublicKey)

	return &rawDerived{
		Address: crypto.PubkeyToAddress(*pubKey),
		PrivKey: privKey,
		PubKey:  *pubKey,
	}, nil
}

func addressEq(a, b common.Address) bool {
	return bytes.Equal(
		a.Bytes(),
		b.Bytes(),
	)
}
