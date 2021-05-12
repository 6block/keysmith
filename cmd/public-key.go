package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"os"

	"github.com/dfinity/keysmith/crypto"
	"github.com/dfinity/keysmith/seed"
)

const PUBLIC_KEY_CMD = "public-key"

type PublicKeyCmd struct {
	FlagSet *flag.FlagSet
	Args    *PublicKeyCmdArgs
}

type PublicKeyCmdArgs struct {
	SeedFile  *string
	Index     *uint
	Protected *bool
	PrivHex   *string
}

func NewPublicKeyCmd() *PublicKeyCmd {
	fset := flag.NewFlagSet(PUBLIC_KEY_CMD, flag.ExitOnError)
	args := &PublicKeyCmdArgs{
		SeedFile:  fset.String("f", "seed.txt", "Seed file."),
		Index:     fset.Uint("i", 0, "Derivation index."),
		Protected: fset.Bool("p", false, "Password protection."),
		PrivHex:   fset.String("x", "", "private key hex str."),
	}
	return &PublicKeyCmd{fset, args}
}

func (cmd *PublicKeyCmd) Run() error {
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

	output := hex.EncodeToString(grandchildECPubKey.SerializeUncompressed())
	fmt.Println(output)
	return nil
}
