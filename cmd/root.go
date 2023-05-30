package cmd

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/spf13/cobra"

	"github.com/niktheblak/passwordhash/pkg/encoder"
)

var (
	encode bool
	salt   []byte
)

var rootCmd = &cobra.Command{
	Use:   "passwordhash",
	Short: "passwordhash is a command line interface to create hashes of passwords",
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&encode, "encode", "e", true, "base64 encode the hash")
	rootCmd.PersistentFlags().BytesHexVarP(&salt, "salt", "s", nil, "salt (optional)")
}

func Execute() error {
	return rootCmd.Execute()
}

func printToConsole(cmd *cobra.Command, prefix, hash, salt []byte) error {
	if encode {
		enc := encoder.Encoder{
			Prefix:   prefix,
			Salt:     salt,
			Hash:     hash,
			Encoding: base64.RawURLEncoding,
		}
		encoded, err := enc.Encode()
		if err != nil {
			return err
		}
		cmd.Println(string(encoded))
	} else {
		if _, err := cmd.OutOrStdout().Write(hash); err != nil {
			return err
		}
	}
	return nil
}

func ensureSalt() error {
	if len(salt) > 0 {
		return nil
	}
	salt = make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	return nil
}
