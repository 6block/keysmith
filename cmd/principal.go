package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dfinity/keysmith/crypto"
	"github.com/dfinity/keysmith/seed"
	"os"

	"github.com/dfinity/keysmith/principal"
)

const PRINCIPAL_CMD = "principal"

type PrincipalCmd struct {
	FlagSet *flag.FlagSet
	Args    *PrincipalCmdArgs
}

type PrincipalCmdArgs struct {
	SeedFile  *string
	Index     *uint
	Protected *bool
	PrivHex   *string
}

func NewPrincipalCmd() *PrincipalCmd {
	fset := flag.NewFlagSet(PRINCIPAL_CMD, flag.ExitOnError)
	args := &PrincipalCmdArgs{
		SeedFile:  fset.String("f", "seed.txt", "Seed file."),
		Index:     fset.Uint("i", 0, "Derivation index."),
		Protected: fset.Bool("p", false, "Password protection."),
		PrivHex:   fset.String("x", "", "private key hex str."),
	}
	return &PrincipalCmd{fset, args}
}

func (cmd *PrincipalCmd) Run() error {
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

	principalId, err := principal.FromECPubKey(grandchildECPubKey)
	if err != nil {
		return err
	}
	fmt.Println(principalId.String())
	return nil
}
