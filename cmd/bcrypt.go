package cmd

import (
	"github.com/spf13/cobra"

	"github.com/niktheblak/passwordhash/pkg/hasher/bcrypt"
	"github.com/niktheblak/passwordhash/pkg/hasher/salted"
)

var bcryptCmd = &cobra.Command{
	Use:   "bcrypt [input data]",
	Short: "Prints bcrypt hash of the input data",
	Long:  `Prints bcrypt hash of the input data provided as the command line argument or STDIN if no command line arguments are specified.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readFromStdin(args)
		if err != nil {
			return err
		}
		if err := ensureSalt(); err != nil {
			return err
		}
		sh := salted.Wrap(new(bcrypt.Bcrypt), salt)
		hash, err := sh.Hash(password)
		if err != nil {
			return err
		}
		return printToConsole(cmd, bcrypt.HashPrefix, hash, salt)
	},
}

func init() {
	rootCmd.AddCommand(bcryptCmd)
}
