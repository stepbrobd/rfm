package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "start the rfm agent daemon",
	RunE:  runAgent,
}

func init() {
	root.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("agent mode is not implemented yet")
}
