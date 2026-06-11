package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is injected at build time via -ldflags "-X main.version=..."
var version string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and exit",
	Run: func(cmd *cobra.Command, args []string) {
		bi, _ := debug.ReadBuildInfo()
		fmt.Fprintln(cmd.OutOrStdout(), resolveVersion(version, bi))
	},
}

func init() {
	root.AddCommand(versionCmd)
}

// prefers the ldflag injected version
// then the module version stamped by the go toolchain
// then a fixed development fallback
func resolveVersion(injected string, bi *debug.BuildInfo) string {
	if injected != "" {
		return injected
	}
	if bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "0-unstable-git"
}
