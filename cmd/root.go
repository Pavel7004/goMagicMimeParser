/*
Copyright © 2023 Kovalev Pavel kovalev5690@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Pavel7004/goMimeMagic/pkg/magic"
)

var (
	debug           bool
	showMask        bool
	showStringValue bool
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
	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Turn on debug info")
	rootCmd.Flags().BoolVarP(&showMask, "with-mask", "m", false, "Print mask")
	rootCmd.Flags().BoolVarP(&showStringValue, "value-as-string", "s", false, "Print value as sequence of characters")
}

func listAll(cmd *cobra.Command, args []string) {
	if !debug {
		log.SetFlags(0)
		log.SetOutput(io.Discard)
	} else {
		log.SetFlags(log.Lshortfile)
	}

	r := magic.NewMagicReader()

	cobra.CheckErr(r.Open())
	defer cobra.CheckErr(r.Close())

	secs, err := r.ReadSections()
	cobra.CheckErr(err)

	for _, sec := range secs {
		fmt.Printf("Filetype: %s\n", sec.Filetype)
		fmt.Printf("Priority: %d\n", sec.Priority)
		for _, con := range sec.Contents {
			if len(sec.Contents) > 1 {
				fmt.Printf(" ~~~~~~~ \n")
			}

			if showStringValue {
				fmt.Printf("Value: %q\n", strings.TrimFunc(string(con.Value), func(r rune) bool {
					return r == '\n'
				}))
			} else {
				fmt.Printf("Value: ")
				for _, c := range con.Value {
					fmt.Printf("%02x ", c)
				}
				fmt.Printf("\n")
			}

			if showMask {
				fmt.Printf("Mask:  ")
				for _, c := range con.Mask {
					fmt.Printf("%02x ", c)
				}
				fmt.Printf("\n")
			}

			fmt.Printf("Indent: %d\n", con.Indent)
			fmt.Printf("Offset: %d\n", con.Offset)
		}
		fmt.Printf(" ------- \n")
	}
}
