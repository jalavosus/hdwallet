package hdwallet

import (
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/pkg/errors"
)

type walletAccount struct {
	derivedAddrs       []*HDWalletAddress
	accountIdx         int
	accountKey         *hdkeychain.ExtendedKey
	lastNonHardenedIdx int
	lastHardenedIdx    int
}

func newWalletAccount(masterKey *hdkeychain.ExtendedKey, accountIdx int, newKeyForAccount bool) *walletAccount {
	subKey := masterKey

	if newKeyForAccount {
		derivePath := addressDerivationPathFromIdx(accountIdx, 0)

		for _, n := range derivePath {
			subKey, _ = subKey.Derive(n)
		}
	}

	return &walletAccount{
		accountIdx:      accountIdx,
		accountKey:      subKey,
		lastHardenedIdx: hdkeychain.HardenedKeyStart,
	}
}

func (w *walletAccount) derive(addressIdx int) (*HDWalletAddress, error) {
	derived, err := deriveNewAdressFromAccountKey(w.accountKey, w.accountIdx, addressIdx)
	if err != nil {
		return nil, errors.Wrap(err, "error deriving new child account")
	}

	fancyDerived := newWalletAddress(derived.PrivKey, derived.PubKey, derived.Address, w.accountIdx, addressIdx)

	w.derivedAddrs = append(w.derivedAddrs, fancyDerived)

	return fancyDerived, nil
}
