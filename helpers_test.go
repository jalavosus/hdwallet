package hdwallet_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testPassphrase string = "hello"
	testMnemonicA  string = "easy unusual trial obscure power asthma like secret soccer human suspect nut concert upon glow shine ship shell attend enter genuine chalk pumpkin section"
	testMnemonicB  string = "hello recycle auto index marble situate noodle cat wheat process chunk matrix risk clown crowd"
)

func TestMnemonicHasAddress(t *testing.T) {
	type args struct {
		addressHex string
		mnemonic   string
		passphrase string
		maxIndex   int
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"testMnemonicA has 0x532147F0c3d63c66cB57B0bc6d552F1c2Ff68BeF",
			args{
				"0x532147F0c3d63c66cB57B0bc6d552F1c2Ff68BeF",
				testMnemonicA,
				"",
				256,
			},
			true,
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, hasAddr, err := hdwallet.MnemonicHasAddress(tt.args.addressHex, tt.args.mnemonic, tt.args.passphrase, tt.args.maxIndex)
			if !tt.wantErr(t, err, fmt.Sprintf("MnemonicHasAddress(%v, %v, %v, %v)", tt.args.addressHex, tt.args.mnemonic, tt.args.passphrase, tt.args.maxIndex)) {
				return
			}
			assert.Equalf(t, tt.want, hasAddr, "MnemonicHasAddress(%v, %v, %v, %v): got %v", tt.args.addressHex, tt.args.mnemonic, tt.args.passphrase, tt.args.maxIndex, addr)
		})
	}
}
