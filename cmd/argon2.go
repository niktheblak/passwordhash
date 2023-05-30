package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/niktheblak/passwordhash/pkg/hasher/argon2"
)

var argon2Cmd = &cobra.Command{
	Use:   "argon2 [input data]",
	Short: "Prints argon2 hash of the input data",
	Long:  `Prints argon2 hash of the input data provided as the command line argument or STDIN if no command line arguments are specified.`,
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
		a := new(argon2.Argon2)
		hash, err := a.HashWithSalt([]byte(password), salt)
		if err != nil {
			return err
		}
		return printToConsole(cmd, nil, hash, salt)
	},
}

func init() {
	rootCmd.AddCommand(argon2Cmd)
}
