package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cryptcli",
	Short: "cryptcli is a command line interface for various hashing functions",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(bcryptCmd)
	rootCmd.AddCommand(scryptCmd)
}
