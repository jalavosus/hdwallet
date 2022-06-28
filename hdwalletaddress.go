package hdwallet

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"

	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var prefix0x = []byte{04} // "0x"

// HDWalletAddress represents a BIP32-compliant derived HD Wallet address (see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki),
// consisting of an on-chain address and ECDSA private/public keys.
type HDWalletAddress struct {
	address         common.Address
	publicKey       ecdsa.PublicKey
	privateKey      *ecdsa.PrivateKey
	transactors     map[uint64]*bind.TransactOpts
	derivationIndex int
	accountIndex    int
	hardened        bool
}

func walletAddressFromPrivateKey(privKey *ecdsa.PrivateKey, accountIndex, derivationIndex int) *HDWalletAddress {
	return newWalletAddress(
		privKey,
		privKey.PublicKey,
		crypto.PubkeyToAddress(privKey.PublicKey),
		accountIndex,
		derivationIndex,
	)
}

func newWalletAddress(privKey *ecdsa.PrivateKey, pubKey ecdsa.PublicKey, address common.Address, accountIdx, addressIdx int) *HDWalletAddress {
	hardened := isHardenedIdx(addressIdx)
	if hardened {
		addressIdx = getHardenedIdx(addressIdx)
	}

	return &HDWalletAddress{
		address:         address,
		privateKey:      privKey,
		publicKey:       pubKey,
		derivationIndex: addressIdx,
		accountIndex:    accountIdx,
		hardened:        hardened,
	}
}

func (a HDWalletAddress) Address() common.Address {
	return a.address
}

func (a HDWalletAddress) PrivateKey() *ecdsa.PrivateKey {
	return a.privateKey
}

func (a HDWalletAddress) PrivateKeyHex() string {
	return common.Bytes2Hex(a.PrivateKeyBytes())
}

func (a HDWalletAddress) PrivateKeyBytes() []byte {
	return bytes.TrimPrefix(
		crypto.FromECDSA(a.privateKey),
		prefix0x,
	)
}

func (a HDWalletAddress) PublicKey() ecdsa.PublicKey {
	return a.publicKey
}

func (a HDWalletAddress) PublicKeyHex() string {
	return common.Bytes2Hex(a.PublicKeyBytes())
}

func (a HDWalletAddress) PublicKeyBytes() []byte {
	return bytes.TrimPrefix(
		crypto.FromECDSAPub(&a.publicKey),
		prefix0x,
	)
}

// TransactOptsForChainID wraps go-ethereum's low-level bind.NewKeyedTransactorWithChainID function,
// returning a keyed *bind.TransactOpts object for the passed chainID.
// If the HDWalletAddress instance has already successfully constructed a transactor for the
// passed chainID, the previously constructed transactor is returned.
// Otherwise, the result of bind.NewKeyedTransactorWithChainID is returned.
func (a *HDWalletAddress) TransactOptsForChainID(chainID *big.Int) (*bind.TransactOpts, error) {
	existingTransactor, ok := a.transactors[chainID.Uint64()]
	if ok {
		return existingTransactor, nil
	}

	newTransactor, err := bind.NewKeyedTransactorWithChainID(a.privateKey, chainID)
	if err != nil {
		return nil, err
	}

	a.transactors[chainID.Uint64()] = newTransactor

	return newTransactor, nil
}

func (a HDWalletAddress) DerivationIndex() int {
	return a.derivationIndex
}

func (a HDWalletAddress) HardenedDerivationIndex() int {
	if a.hardened {
		return hdkeychain.HardenedKeyStart + a.derivationIndex
	}

	return a.derivationIndex
}

func (a HDWalletAddress) DerivationPath() string {
	return addressDerivationPathFromIdx(a.accountIndex, a.HardenedDerivationIndex()).String()
}

func (a HDWalletAddress) Hardened() bool {
	return a.hardened
}
