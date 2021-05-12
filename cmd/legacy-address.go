package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dfinity/keysmith/crypto"
	"github.com/dfinity/keysmith/seed"
	"os"
	"strings"

	eth "github.com/ethereum/go-ethereum/crypto"
)

const LEGACY_ADDRESS_CMD = "legacy-address"

type LegacyAddressCmd struct {
	FlagSet *flag.FlagSet
	Args    *LegacyAddressCmdArgs
}

type LegacyAddressCmdArgs struct {
	SeedFile  *string
	Index     *uint
	Protected *bool
	PrivHex   *string
}

func NewLegacyAddressCmd() *LegacyAddressCmd {
	fset := flag.NewFlagSet(LEGACY_ADDRESS_CMD, flag.ExitOnError)
	args := &LegacyAddressCmdArgs{
		SeedFile:  fset.String("f", "seed.txt", "Seed file."),
		Index:     fset.Uint("i", 0, "Derivation index."),
		Protected: fset.Bool("p", false, "Password protection."),
		PrivHex:   fset.String("x", "", "private key hex str."),
	}
	return &LegacyAddressCmd{fset, args}
}

func (cmd *LegacyAddressCmd) Run() error {
	cmd.FlagSet.Parse(os.Args[2:])
	var grandchildECPubKey *btcec.PublicKey

	if len(*cmd.Args.PrivHex) > 0 {
		pkbytes, err := hex.DecodeString(*cmd.Args.PrivHex)
		if err != nil {
			return err
		}
		_, grandchildECPubKey = btcec.PrivKeyFromBytes(btcec.S256(), pkbytes)
	} else {
		seed, err := seed.Load(*cmd.Args.SeedFile, *cmd.Args.Protected)
		if err != nil {
			return err
		}
		masterXPrivKey, err := crypto.DeriveMasterXPrivKey(seed)
		if err != nil {
			return err
		}
		_, grandchildECPubKey, err = crypto.DeriveGrandchildECKeyPair(
			masterXPrivKey,
			uint32(*cmd.Args.Index),
		)
		if err != nil {
			return err
		}
	}

	address := eth.PubkeyToAddress(*grandchildECPubKey.ToECDSA())
	output := strings.ToLower(strings.TrimPrefix(address.String(), "0x"))
	fmt.Println(output)
	return nil
}
