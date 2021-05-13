package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dfinity/keysmith/crypto"
	"github.com/dfinity/keysmith/seed"
	"os"

	"github.com/dfinity/keysmith/account"
)

const ACCOUNT_CMD = "account"

type AccountCmd struct {
	FlagSet *flag.FlagSet
	Args    *AccountCmdArgs
}

type AccountCmdArgs struct {
	SeedFile        *string
	Index           *uint
	Protected       *bool
	PrivHex         *string
	NoCheckSumBytes *bool
}

func NewAccountCmd() *AccountCmd {
	fset := flag.NewFlagSet(ACCOUNT_CMD, flag.ExitOnError)
	args := &AccountCmdArgs{
		SeedFile:        fset.String("f", "seed.txt", "Seed file."),
		Index:           fset.Uint("i", 0, "Derivation index."),
		Protected:       fset.Bool("p", false, "Password protection."),
		PrivHex:         fset.String("x", "", "private key hex str."),
		NoCheckSumBytes: fset.Bool("b", false, "Without checksum bytes."),
	}
	return &AccountCmd{fset, args}
}

func (cmd *AccountCmd) Run() error {
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

	accountId, err := account.FromECPubKey(grandchildECPubKey)
	if err != nil {
		return err
	}

	if *cmd.Args.NoCheckSumBytes {
		bb, _ := hex.DecodeString(accountId.String())
		for i := 4; i < len(bb); i++ {
			fmt.Printf("%d:nat8; ", bb[i])
		}
		fmt.Println()
	} else {
		fmt.Println(accountId.String())
	}
	return nil
}
