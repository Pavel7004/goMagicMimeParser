/*
Copyright © 2023 Kovalev Pavel kovalev5690@gmail.com
*/package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/Pavel7004/goMimeMagic/pkg/magic"
)

var rootCmd = &cobra.Command{
	Use:   "magic",
	Short: "Utility that parses MIME types binary file",
	Long: `goMimeMagic is a utility that reads magic binary file
to get binary signatures for filetypes.

Example: magic
This will print all types and their signatures.`,
	Run: listAll,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func listAll(cmd *cobra.Command, args []string) {
	r := magic.NewMagicReader()

	cobra.CheckErr(r.Open())
	defer cobra.CheckErr(r.Close())
}
