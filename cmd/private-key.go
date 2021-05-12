package cmd

import (
	"encoding/hex"
	"flag"
	"github.com/btcsuite/btcd/btcec"
	"os"

	"github.com/dfinity/keysmith/codec"
	"github.com/dfinity/keysmith/crypto"
	"github.com/dfinity/keysmith/seed"
)

const PRIVATE_KEY_CMD = "private-key"

type PrivateKeyCmd struct {
	FlagSet *flag.FlagSet
	Args    *PrivateKeyCmdArgs
}

type PrivateKeyCmdArgs struct {
	Index      *uint
	OutputFile *string
	Protected  *bool
	SeedFile   *string
	PrivHex    *string
}

func NewPrivateKeyCmd() *PrivateKeyCmd {
	fset := flag.NewFlagSet(PRIVATE_KEY_CMD, flag.ExitOnError)
	args := &PrivateKeyCmdArgs{
		Index:      fset.Uint("i", 0, "Derivation index."),
		OutputFile: fset.String("o", "identity.pem", "Output file."),
		Protected:  fset.Bool("p", false, "Password protection."),
		SeedFile:   fset.String("f", "seed.txt", "Seed file."),
		PrivHex:    fset.String("x", "", "private key hex str."),
	}
	return &PrivateKeyCmd{fset, args}
}

func (cmd *PrivateKeyCmd) Run() error {
	cmd.FlagSet.Parse(os.Args[2:])

	var grandchildECPrivKey *btcec.PrivateKey
	if len(*cmd.Args.PrivHex) > 0 {
		pkbytes, err := hex.DecodeString(*cmd.Args.PrivHex)
		if err != nil {
			return err
		}
		grandchildECPrivKey, _ = btcec.PrivKeyFromBytes(btcec.S256(), pkbytes)
	} else {
		seed, err := seed.Load(*cmd.Args.SeedFile, *cmd.Args.Protected)
		if err != nil {
			return err
		}
		masterXPrivKey, err := crypto.DeriveMasterXPrivKey(seed)
		if err != nil {
			return err
		}
		grandchildECPrivKey, _, err = crypto.DeriveGrandchildECKeyPair(
			masterXPrivKey,
			uint32(*cmd.Args.Index),
		)
		if err != nil {
			return err
		}
	}

	output, err := codec.ECPrivKeyToPEM(grandchildECPrivKey)
	if err != nil {
		return err
	}
	return writeFileOrStdout(*cmd.Args.OutputFile, output, 0600)
}
