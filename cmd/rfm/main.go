package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// main prints a failed command's error once, cobra would print it a second
// time and the usage with it, which a runtime error does not call for
var root = &cobra.Command{
	Use:           "rfm",
	Short:         "Router Flow Monitor",
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	root.PersistentFlags().BoolP("help", "h", false, "Print help and exit")
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
