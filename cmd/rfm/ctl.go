package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"ysun.co/rfm/ctl"
)

// the birdc style commands talk to a running agent over its control socket

var (
	ctlSocket string
	ctlJSON   bool
)

func ctlClient() *ctl.Client {
	return &ctl.Client{Socket: ctlSocket}
}

// emit prints v as json when --json is set and returns true
func emit(cmd *cobra.Command, v any) bool {
	if !ctlJSON {
		return false
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return true
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the running agent",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := ctlClient().Status()
		if err != nil {
			return err
		}
		if emit(cmd, st) {
			return nil
		}
		printStatus(cmd.OutOrStdout(), st)
		return nil
	},
}

func printStatus(w io.Writer, st ctl.Status) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "version\t%s\n", st.Version)
	fmt.Fprintf(tw, "uptime\t%s\n", st.Uptime)
	names := make([]string, 0, len(st.Interfaces))
	for _, iface := range st.Interfaces {
		names = append(names, iface.Name)
	}
	fmt.Fprintf(tw, "interfaces\t%s\n", strings.Join(names, " "))
	sampling := fmt.Sprintf("1 in %d", st.Sampling.Rate)
	if st.Sampling.Adaptive {
		sampling += fmt.Sprintf(" (adaptive, base %d, max %d)", st.Sampling.Base, st.Sampling.Max)
	}
	fmt.Fprintf(tw, "sampling\t%s\n", sampling)
	fmt.Fprintf(tw, "flows\t%d active of %d, %d ring drops, %d forced evictions, %d folded under empty labels\n",
		st.Flows.Active, st.Flows.Max, st.Flows.DroppedEvents, st.Flows.ForcedEvictions, st.Flows.Folded)
	if st.IPFIX != nil {
		state := "disconnected"
		if st.IPFIX.Connected {
			state = "connected"
		}
		var errs []string
		for errno, n := range st.IPFIX.SendErrors {
			errs = append(errs, fmt.Sprintf("%s=%d", errno, n))
		}
		line := fmt.Sprintf("%s %s, %d messages, %d records, %d queue drops, %d unsent, %d failed to encode, %d lost in failed sends",
			st.IPFIX.Collector, state, st.IPFIX.Messages, st.IPFIX.Records, st.IPFIX.QueueDropped, st.IPFIX.Unsent, st.IPFIX.EncodeErrors, st.IPFIX.SendFailed)
		if len(errs) > 0 {
			line += ", send errors " + strings.Join(errs, " ")
		}
		fmt.Fprintf(tw, "ipfix\t%s\n", line)
	}
	if st.MMDB != nil {
		fmt.Fprintf(tw, "mmdb\tasn %s, city %s\n", epoch(st.MMDB.ASNBuildEpoch), epoch(st.MMDB.CityBuildEpoch))
	}
	if st.RIB != nil {
		fmt.Fprintf(tw, "rib\t%s, %d ipv4 and %d ipv6 prefixes, %d routes in %d views\n",
			st.RIB.Listen, st.RIB.PrefixesV4, st.RIB.PrefixesV6, st.RIB.Routes, st.RIB.Peers)
	}
	tw.Flush()
}

func epoch(e uint) string {
	if e == 0 {
		return "none"
	}
	return time.Unix(int64(e), 0).UTC().Format("2006-01-02")
}

var flowsCmd = &cobra.Command{
	Use:   "flows",
	Short: "Inspect the live flow table",
}

var flowsTopBy string

var flowsTopCmd = &cobra.Command{
	Use:   "top [N]",
	Short: "Show the busiest live flows",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		n := 20
		if len(args) == 1 {
			parsed, err := strconv.Atoi(args[0])
			if err != nil || parsed < 1 {
				return fmt.Errorf("the count must be a positive integer, got %q", args[0])
			}
			n = parsed
		}
		rows, err := ctlClient().FlowsTop(n, flowsTopBy)
		if err != nil {
			return err
		}
		if emit(cmd, rows) {
			return nil
		}
		printFlows(cmd.OutOrStdout(), rows)
		return nil
	},
}

func printFlows(w io.Writer, rows []ctl.FlowRow) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "IFACE\tDIR\tPROTO\tSRC\tDST\tSRC ASN\tDST ASN\tPACKETS\tBYTES\tAGE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			r.Interface, r.Direction, r.Proto,
			endpoint(r.Src, r.SrcPort), endpoint(r.Dst, r.DstPort),
			asn(r.SrcASN), asn(r.DstASN),
			r.EstPackets, r.EstBytes,
			time.Since(r.FirstSeen).Round(time.Second))
	}
	tw.Flush()
}

func endpoint(addr netip.Addr, port uint16) string {
	if port == 0 {
		return addr.String()
	}
	return netip.AddrPortFrom(addr, port).String()
}

func asn(n uint32) string {
	if n == 0 {
		return "-"
	}
	return strconv.FormatUint(uint64(n), 10)
}

var flowsCountCmd = &cobra.Command{
	Use:   "count",
	Short: "Count the live flows",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		n, err := ctlClient().FlowsCount()
		if err != nil {
			return err
		}
		if emit(cmd, n) {
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), n)
		return nil
	},
}

var ribCmd = &cobra.Command{
	Use:   "rib",
	Short: "Inspect the BMP fed routing table",
}

var ribLookupCmd = &cobra.Command{
	Use:   "lookup <address>",
	Short: "Show the best route for an address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, err := netip.ParseAddr(args[0])
		if err != nil {
			return err
		}
		route, err := ctlClient().RIBLookup(addr)
		if err != nil {
			return err
		}
		if emit(cmd, route) {
			return nil
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 8, 2, ' ', 0)
		fmt.Fprintf(tw, "prefix\t%s\n", route.Prefix)
		origin := asn(route.OriginASN)
		if route.OriginASSet {
			origin = "ambiguous (AS_SET)"
		}
		fmt.Fprintf(tw, "origin\t%s\n", origin)
		fmt.Fprintf(tw, "as path\t%s\n", joinASNs(route.ASPath))
		if len(route.Communities) > 0 {
			fmt.Fprintf(tw, "communities\t%s\n", strings.Join(route.Communities, " "))
		}
		if len(route.LargeCommunities) > 0 {
			fmt.Fprintf(tw, "large communities\t%s\n", strings.Join(route.LargeCommunities, " "))
		}
		if route.Truncated {
			fmt.Fprintf(tw, "truncated\tas path and communities show only the leading values rfm keeps\n")
		}
		view := "pre policy"
		if route.PostPolicy {
			view = "post policy"
		}
		fmt.Fprintf(tw, "peer\t%s AS%d (%s)\n", route.PeerAddress, route.PeerASN, view)
		tw.Flush()
		return nil
	},
}

func joinASNs(path []uint32) string {
	parts := make([]string, len(path))
	for i, n := range path {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, " ")
}

var ribSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Count prefixes, routes and the views that hold them",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := ctlClient().RIBSummary()
		if err != nil {
			return err
		}
		if emit(cmd, s) {
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %d ipv4 and %d ipv6 prefixes, %d routes in %d views\n",
			s.Listen, s.PrefixesV4, s.PrefixesV6, s.Routes, s.Peers)
		return nil
	},
}

var setCmd = &cobra.Command{
	Use:   "set",
	Short: "Change a running agent",
}

var setSampleRateCmd = &cobra.Command{
	Use:   "sample-rate <N>",
	Short: "Sample 1 in N skbs from now on",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rate, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil || rate == 0 {
			return fmt.Errorf("the rate must be a positive integer, got %q", args[0])
		}
		if err := ctlClient().SetSampleRate(uint32(rate)); err != nil {
			return err
		}
		if emit(cmd, ctl.Sampling{Rate: uint32(rate)}) {
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "sampling 1 in %d\n", rate)
		return nil
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect the agent configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the configuration the agent loaded",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		text, err := ctlClient().ConfigShow()
		if err != nil {
			return err
		}
		if emit(cmd, text) {
			return nil
		}
		fmt.Fprint(cmd.OutOrStdout(), text)
		return nil
	},
}

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload data the agent serves",
}

var reloadMMDBCmd = &cobra.Command{
	Use:   "mmdb",
	Short: "Re-open the MMDB databases when the files changed",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ctlClient().ReloadMMDB(); err != nil {
			return err
		}
		if !emit(cmd, "reloaded") {
			fmt.Fprintln(cmd.OutOrStdout(), "reloaded")
		}
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{statusCmd, flowsCmd, ribCmd, setCmd, configCmd, reloadCmd} {
		c.PersistentFlags().StringVar(&ctlSocket, "socket", ctl.DefaultSocket, "Control socket of the agent")
		c.PersistentFlags().BoolVar(&ctlJSON, "json", false, "Print the result as JSON")
		root.AddCommand(c)
	}
	flowsTopCmd.Flags().StringVar(&flowsTopBy, "by", "bytes", "Order by bytes or packets")
	flowsCmd.AddCommand(flowsTopCmd, flowsCountCmd)
	ribCmd.AddCommand(ribLookupCmd, ribSummaryCmd)
	setCmd.AddCommand(setSampleRateCmd)
	configCmd.AddCommand(configShowCmd)
	reloadCmd.AddCommand(reloadMMDBCmd)
}
