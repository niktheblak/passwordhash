package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/niktheblak/passwordhash/pkg/hasher/scrypt"
)

var scryptCmd = &cobra.Command{
	Use:   "scrypt [input data]",
	Short: "Prints scrypt hash of the input data",
	Long:  `Prints scrypt hash with a random salt prefix of the input data provided as the command line argument or STDIN if no command line arguments are specified.`,
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var password string
		if len(args) == 0 {
			if _, err := fmt.Fscan(cmd.InOrStdin(), &password); err != nil {
				log.Fatal(err)
			}
		} else {
			password = args[0]
		}
		if err := ensureSalt(); err != nil {
			return err
		}
		s := new(scrypt.Scrypt)
		hash, err := s.HashWithSalt([]byte(password), salt)
		if err != nil {
			return err
		}
		return printToConsole(cmd, scrypt.HashPrefix, hash, salt)
	},
}

func init() {
	rootCmd.AddCommand(scryptCmd)
}
