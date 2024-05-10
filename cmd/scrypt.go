package cmd

import (
	"github.com/spf13/cobra"

	"github.com/niktheblak/passwordhash/pkg/hasher/scrypt"
)

var scryptCmd = &cobra.Command{
	Use:   "scrypt [input data]",
	Short: "Prints scrypt hash of the input data",
	Long:  `Prints scrypt hash with a random salt prefix of the input data provided as the command line argument or STDIN if no command line arguments are specified.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readFromStdin(args)
		if err != nil {
			return err
		}
		if err := ensureSalt(); err != nil {
			return err
		}
		s := new(scrypt.Scrypt)
		hash, err := s.HashWithSalt(password, salt)
		if err != nil {
			return err
		}
		return printToConsole(cmd, scrypt.HashPrefix, hash, salt)
	},
}

func init() {
	rootCmd.AddCommand(scryptCmd)
}
