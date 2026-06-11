package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var root = &cobra.Command{
	Use:   "rfm",
	Short: "Router Flow Monitor",
}

func init() {
	root.PersistentFlags().BoolP("help", "h", false, "Print help and exit")
	root.PersistentFlags().StringVarP(&cfgFile, "config", "c",
		"/etc/rfm/rfm.toml", "RFM configuration file path")
}

// cobra generates the help and completion commands during Execute
// too late to override
func overrideGeneratedCommands() {
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		switch c.Name() {
		case "help":
			c.Short = "Show help for any command"
		case "completion":
			for _, sub := range c.Commands() {
				if f := sub.Flags().Lookup("no-descriptions"); f != nil {
					f.Usage = "Disable completion descriptions"
				}
			}
		}
	}
}

func main() {
	overrideGeneratedCommands()

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "rfm: %v\n", err)
		os.Exit(1)
	}
}
