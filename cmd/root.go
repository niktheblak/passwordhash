package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "passwordhash",
	Short: "passwordhash is a command line interface to create hashes of passwords",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(bcryptCmd)
	rootCmd.AddCommand(scryptCmd)
}
