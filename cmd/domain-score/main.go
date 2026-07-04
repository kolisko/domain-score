package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kolisko/domain-score/internal/audit"
	"github.com/kolisko/domain-score/internal/checks"
	"github.com/kolisko/domain-score/internal/report"
	"github.com/kolisko/domain-score/internal/runner"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type scanFlags struct {
	format     string
	out        string
	profile    string
	aggressive bool
	enable     []string
	disable    []string
	timeout    time.Duration
	userAgent  string
	weights    string
}

func main() {
	root := &cobra.Command{
		Use:           "domain-score",
		Short:         "Audit publicly visible domain security, SEO, performance and AI-readiness signals.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(scanCommand(), listChecksCommand(), explainCommand(), versionCommand())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func scanCommand() *cobra.Command {
	flags := scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan <domain>",
		Short: "Run a domain audit",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := audit.ParseTarget(args[0])
			if err != nil {
				return err
			}
			var weights []byte
			if flags.weights != "" {
				weights, err = os.ReadFile(flags.weights)
				if err != nil {
					return err
				}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), flags.timeout*time.Duration(4))
			defer cancel()
			r, err := runner.Run(ctx, target, runner.Options{
				Profile:     flags.profile,
				Aggressive:  flags.aggressive,
				Enable:      flags.enable,
				Disable:     flags.disable,
				Timeout:     flags.timeout,
				UserAgent:   flags.userAgent,
				WeightsYAML: weights,
				Version:     version,
			})
			if err != nil {
				return err
			}
			return writeOutputs(r, flags)
		},
	}
	cmd.Flags().StringVar(&flags.format, "format", "json,md", "Comma-separated output formats: json,md")
	cmd.Flags().StringVar(&flags.out, "out", ".", "Output directory, or '-' for stdout")
	cmd.Flags().StringVar(&flags.profile, "profile", "safe", "Scan profile: safe, standard, aggressive")
	cmd.Flags().BoolVar(&flags.aggressive, "aggressive", false, "Enable all aggressive checks and evidence collectors")
	cmd.Flags().StringSliceVar(&flags.enable, "enable", nil, "Enable specific check IDs, including aggressive checks")
	cmd.Flags().StringSliceVar(&flags.disable, "disable", nil, "Disable specific check IDs")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 8*time.Second, "Per-request timeout")
	cmd.Flags().StringVar(&flags.userAgent, "user-agent", "", "Custom User-Agent")
	cmd.Flags().StringVar(&flags.weights, "weights", "", "YAML file overriding check weights: weights: {check.id: 3}")
	return cmd
}

func writeOutputs(r audit.Report, flags scanFlags) error {
	formats := splitCSV(flags.format)
	if flags.out != "-" {
		if err := os.MkdirAll(flags.out, 0o755); err != nil {
			return err
		}
	}
	for _, f := range formats {
		var data []byte
		var err error
		var name string
		switch f {
		case "json":
			data, err = report.JSON(r)
			name = "report.json"
		case "md", "markdown":
			data = report.Markdown(r)
			name = "report.md"
		default:
			return fmt.Errorf("unsupported format %q", f)
		}
		if err != nil {
			return err
		}
		if flags.out == "-" {
			fmt.Printf("--- %s ---\n%s\n", name, string(data))
			continue
		}
		if err := os.WriteFile(filepath.Join(flags.out, name), data, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "domain-score: %s scored %d/100 (%s)\n", r.Target.Domain, r.Score.Overall, r.Score.Grade)
	return nil
}

func listChecksCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list-checks",
		Short: "List available checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			all := checks.Registry()
			sort.Slice(all, func(i, j int) bool { return all[i].Meta().ID < all[j].Meta().ID })
			for _, check := range all {
				m := check.Meta()
				fmt.Fprintf(cmd.OutOrStdout(), "%-42s %-14s %-12s weight=%d severity=%s\n", m.ID, m.Category, m.Mode, m.Weight, m.Severity)
			}
			return nil
		},
	}
}

func explainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <check-id>",
		Short: "Explain one check",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, check := range checks.Registry() {
				m := check.Meta()
				if m.ID != args[0] {
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n", m.Title)
				fmt.Fprintf(cmd.OutOrStdout(), "ID: %s\nCategory: %s\nMode: %s\nWeight: %d\nSeverity: %s\n", m.ID, m.Category, m.Mode, m.Weight, m.Severity)
				if len(m.Tags) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "Tags: %s\n", strings.Join(m.Tags, ", "))
				}
				if m.Docs != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "Docs: %s\n", m.Docs)
				}
				return nil
			}
			return fmt.Errorf("unknown check %q", args[0])
		},
	}
}

func versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "domain-score %s (%s, %s)\n", version, commit, date)
		},
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
