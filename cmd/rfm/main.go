package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var root = &cobra.Command{
	Use:   "rfm",
	Short: "router flow monitor",
}

func init() {
	root.PersistentFlags().StringVar(&cfgFile, "config",
		"/etc/rfm/rfm.toml", "config file path")
}

func main() {
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "rfm: %v\n", err)
		os.Exit(1)
	}
}
