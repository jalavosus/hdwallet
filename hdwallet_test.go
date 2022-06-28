package hdwallet_test

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	"github.com/jalavosus/hdwallet-go"
)

func TestNewHDWallet(t *testing.T) {
	tests := []struct {
		name    string
		args    []hdwallet.NewWalletOpt
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"no args",
			nil,
			assert.NoError,
		},
		{
			"with passphrase",
			[]hdwallet.NewWalletOpt{
				hdwallet.WithPassphrase("1234567890"),
			},
			assert.NoError,
		},
		{
			"with mnemonic",
			[]hdwallet.NewWalletOpt{
				hdwallet.WithMnemonic(testMnemonicA),
			},
			assert.NoError,
		},
		{
			"with entropy",
			[]hdwallet.NewWalletOpt{
				hdwallet.WithEntropy(hdwallet.EntropyFromString("b689a63adcc87720ebf67d8e4b9e8dd9156b1dab182665b904959f0ef9f9873f")),
			},
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hdwallet.NewHDWallet(tt.args...)

			if !tt.wantErr(t, err, fmt.Sprintf("NewHDWallet(%v)", tt.args)) {
				return
			}

			assert.NotNilf(t, got, "NewHDWallet(%v) returned nil", tt.args)
		})
	}
}

type hdWalletDeriveAccountTestCase struct {
	opts    []hdwallet.NewWalletOpt
	wantErr assert.ErrorAssertionFunc
}

type hdWalletDeriveAccountFromIndexTestCase struct {
	hdWalletDeriveAccountTestCase
	hardened bool
	want     common.Address
	idx      int
}

func TestHDWallet(t *testing.T) {
	testOpts := [][]hdwallet.NewWalletOpt{
		{hdwallet.WithMnemonic(testMnemonicA)},
		{
			hdwallet.WithMnemonic(testMnemonicA),
			hdwallet.WithPassphrase(testPassphrase),
		},
		{
			hdwallet.WithMnemonic(testMnemonicA),
			hdwallet.WithDeriveKeyForAccount(true),
		},
		{hdwallet.WithMnemonic(testMnemonicB)},
		{
			hdwallet.WithMnemonic(testMnemonicB),
			hdwallet.WithPassphrase(testPassphrase),
		},
	}

	var (
		deriveTests        []hdWalletDeriveAccountTestCase
		deriveFromIdxTests []hdWalletDeriveAccountFromIndexTestCase
	)

	for _, opts := range testOpts {
		deriveTests = append(deriveTests, hdWalletDeriveAccountTestCase{opts, assert.NoError})
	}

	for i, tc := range deriveTests {
		var (
			wantAddr, wantAddrHardened common.Address
		)
		switch i {
		case 0:
			wantAddr = common.HexToAddress("0x7138E074701db5F88a3eAFBA50C9cb262Cf215c9")
			wantAddrHardened = common.HexToAddress("0x064bF669fCda7714936200475C5970c44039f3A3")
		case 1:
			wantAddr = common.HexToAddress("0x8b28c0AAac0EFf6FB83B62ee985D4b70f7c98A18")
			wantAddrHardened = common.HexToAddress("0x8FEaC17CdAFAfbAD14A9303fcf1Aebbfa2BA4d2C")
		case 2:
			wantAddr = common.HexToAddress("0x9B90D47a8BD1Ceff2B3FD2281cb272ad677cd55b")
			wantAddrHardened = common.HexToAddress("0x0000000000000000000000000000000000000000")
		case 3:
			wantAddr = common.HexToAddress("0xEd296D9E37D6C9Eb198B0C29667A064f1043B447")
			wantAddrHardened = common.HexToAddress("0x793dE04E16aae74782230ABB7FE1f6a63515Ae19")
		case 4:
			wantAddr = common.HexToAddress("0xeBbC06CF6dd93cf74Dd4D7AaeCdf47278b86fD17")
			wantAddrHardened = common.HexToAddress("0xB5F090251A21fa99F30B96D7C2953e948aF79D56")
		}

		idx := 49

		deriveFromIdxTests = append(deriveFromIdxTests, hdWalletDeriveAccountFromIndexTestCase{
			hdWalletDeriveAccountTestCase: tc,
			hardened:                      false,
			want:                          wantAddr,
			idx:                           idx,
		})

		if wantAddrHardened.String() != common.HexToAddress("0x0000000000000000000000000000000000000000").String() {
			deriveFromIdxTests = append(deriveFromIdxTests, hdWalletDeriveAccountFromIndexTestCase{
				hdWalletDeriveAccountTestCase: tc,
				hardened:                      true,
				want:                          wantAddrHardened,
				idx:                           idx + hdkeychain.HardenedKeyStart,
			})
		}
	}

	t.Run("DeriveAddress", testHDWalletDeriveAccount(deriveTests))
	t.Run("DeriveHardenedAddress", testHDWalletDeriveHardenedAccount(deriveTests))
	t.Run("DeriveFromIndex", testHDWalletDeriveAccountFromIndex(deriveFromIdxTests))
}

func testHDWalletDeriveAccount(tests []hdWalletDeriveAccountTestCase) func(*testing.T) {
	return func(t *testing.T) {
		for _, tt := range tests {
			t.Run("", testHDWalletDerive(tt, false))
		}
	}
}

func testHDWalletDeriveHardenedAccount(tests []hdWalletDeriveAccountTestCase) func(*testing.T) {
	return func(t *testing.T) {
		for _, tt := range tests {
			t.Run("", testHDWalletDerive(tt, true))
		}
	}
}

func testHDWalletDeriveAccountFromIndex(tests []hdWalletDeriveAccountFromIndexTestCase) func(*testing.T) {
	return func(t *testing.T) {
		for _, tt := range tests {
			t.Run("", testHDWalletDeriveFromIdx(tt))
		}
	}
}

func testHDWalletDerive(tt hdWalletDeriveAccountTestCase, hardened bool) func(t *testing.T) {
	return func(t *testing.T) {
		w, err := hdwallet.NewHDWallet(tt.opts...)
		assert.Nil(t, err)
		assert.NotNil(t, w)

		var (
			errStr string
			tFunc  func() (*hdwallet.HDWalletAddress, error)
		)

		if hardened {
			errStr = "DeriveHardenedAddress()"
			tFunc = w.DeriveHardenedAddress
		} else {
			errStr = "DeriveAddress()"
			tFunc = w.DeriveAddress
		}

		got, err := tFunc()
		if !tt.wantErr(t, err, fmt.Sprintf(errStr)) {
			return
		}

		assert.NotNil(t, got)
		assert.NotEmpty(t, w.Accounts())
	}
}

func testHDWalletDeriveFromIdx(tt hdWalletDeriveAccountFromIndexTestCase) func(t *testing.T) {
	return func(t *testing.T) {
		w, err := hdwallet.NewHDWallet(tt.opts...)
		assert.Nil(t, err)
		assert.NotNil(t, w)

		errStr := "DeriveAddressFromIndex()"
		tFunc := w.DeriveAddressFromIndex

		got, err := tFunc(tt.idx)
		if !tt.wantErr(t, err, fmt.Sprintf(errStr)) {
			return
		}

		assert.NotNil(t, got)
		assert.NotEmpty(t, w.Accounts())

		assert.Equal(t, tt.want.String(), got.Address().String())
	}
}

func BenchmarkDeriveAccount(b *testing.B) {
	b.Run("serial", func(b *testing.B) {
		b.Skip()
		w, err := hdwallet.NewHDWallet()
		if err != nil {
			b.Fatal(err)
		}

		for i := 0; i < b.N; i++ {
			_, _ = w.DeriveAddress()
		}
	})

	b.Run("parallel", func(b *testing.B) {
		w, err := hdwallet.NewHDWallet()
		if err != nil {
			b.Fatal(err)
		}

		b.RunParallel(benchmarkDeriveParallel(b, w, false))
	})

	b.Run("parallel-new_wallet", func(b *testing.B) {
		b.RunParallel(benchmarkDeriveParallelNewWallet(b, false))
	})
}

func BenchmarkDeriveHardenedAccount(b *testing.B) {
	b.Run("serial", func(b *testing.B) {
		b.Skip()
		w, err := hdwallet.NewHDWallet()
		if err != nil {
			b.Fatal(err)
		}

		for i := 0; i < b.N; i++ {
			_, _ = w.DeriveHardenedAddress()
		}
	})

	b.Run("parallel", func(b *testing.B) {
		w, err := hdwallet.NewHDWallet()
		if err != nil {
			b.Fatal(err)
		}

		b.RunParallel(benchmarkDeriveParallel(b, w, true))
	})

	b.Run("parallel-new_wallet", func(b *testing.B) {
		b.RunParallel(benchmarkDeriveParallelNewWallet(b, true))
	})
}

func BenchmarkDeriveAll(b *testing.B) {
	b.Run("parallel", func(b *testing.B) {
		w, err := hdwallet.NewHDWallet()
		if err != nil {
			b.Fatal(err)
		}

		b.RunParallel(benchmarkDeriveParallel(b, w, true))
		b.RunParallel(benchmarkDeriveParallel(b, w, false))
	})

	b.Run("parallel-new_wallet", func(b *testing.B) {
		b.RunParallel(benchmarkDeriveParallelNewWallet(b, true))
		b.RunParallel(benchmarkDeriveParallelNewWallet(b, false))
	})
}

func benchmarkDeriveParallelNewWallet(b *testing.B, hardened bool) func(*testing.PB) {
	w, err := hdwallet.NewHDWallet()
	if err != nil {
		b.Fatal(err)
	}

	return func(pb *testing.PB) {
		for pb.Next() {
			switch hardened {
			case true:
				_, _ = w.DeriveHardenedAddress()
			case false:
				_, _ = w.DeriveAddress()
			}
		}
	}
}

func benchmarkDeriveParallel(_ *testing.B, w *hdwallet.HDWallet, hardened bool) func(*testing.PB) {
	return func(pb *testing.PB) {
		for pb.Next() {
			switch hardened {
			case true:
				_, _ = w.DeriveHardenedAddress()
			case false:
				_, _ = w.DeriveAddress()
			}
		}
	}
}
