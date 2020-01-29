package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/niktheblak/passwordhash/pkg/scrypt"
	"github.com/spf13/cobra"
)

var scryptCmd = &cobra.Command{
	Use:   "scrypt [input data]",
	Short: "Prints scrypt hash of the input data",
	Long:  `Prints scrypt hash with a random salt prefix of the input data provided as the command line argument or STDIN if no command line arguments are specified.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var password string
		if len(args) == 0 {
			if _, err := fmt.Fscan(os.Stdin, &password); err != nil {
				log.Fatal(err)
			}
		} else {
			password = args[0]
		}
		hash, err := scrypt.GenerateFromPassword([]byte(password))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(hash))
	},
}
