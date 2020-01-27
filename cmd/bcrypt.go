package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var bcryptCmd = &cobra.Command{
	Use:   "bcrypt",
	Short: "Prints bcrypt hash of the input data",
	Long:  `Prints bcrypt hash of the input data provided as the command line argument or STDIN if no command line arguments are specified.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var password string
		if len(os.Args) == 0 {
			if _, err := fmt.Fscan(os.Stdin, &password); err != nil {
				log.Fatal(err)
			}
		} else {
			password = os.Args[0]
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(hash))
	},
}
