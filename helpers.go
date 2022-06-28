package hdwallet

import (
	"github.com/ethereum/go-ethereum/common"
)

func MnemonicHasAddress(addressHex, mnemonic, passphrase string, maxIndex int) (common.Address, bool, error) {
	wallet, err := NewHDWallet(WithPassphrase(passphrase), WithMnemonic(mnemonic))
	if err != nil {
		return common.Address{}, false, err
	}

	for i := 0; i < maxIndex; i++ {
		newAddr, err := wallet.DeriveAddress()
		if err != nil {
			return common.Address{}, false, err
		}

		if addressEq(common.HexToAddress(addressHex), newAddr.address) {
			return newAddr.Address(), true, nil
		}
	}

	return common.Address{}, false, nil
}
