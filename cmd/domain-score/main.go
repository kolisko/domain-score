package main

import (
	"context"
	"fmt"
	"net/http"
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
	"github.com/kolisko/domain-score/internal/selfupdate"
	exttools "github.com/kolisko/domain-score/internal/tools"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type scanFlags struct {
	format        string
	out           string
	profile       string
	aggressive    bool
	enable        []string
	disable       []string
	timeout       time.Duration
	userAgent     string
	weights       string
	noColor       bool
	sort          string
	details       string
	detailCheck   string
	tools         string
	toolRuntime   string
	toolsImage    string
	toolsPull     string
	toolsTimeout  time.Duration
	toolsCacheDir string
}

func main() {
	root := &cobra.Command{
		Use:   "domain-score",
		Short: "Audit publicly visible domain security, SEO, performance and AI-readiness signals.",
		Long: `Domain Score audits one public domain at a time.

Start with:
  domain-score scan example.com

The domain name is the required argument after "scan". Use a bare domain
such as example.com, or a URL such as https://example.com.`,
		Example: `  domain-score scan example.com
  domain-score scan https://example.com --format json,md --out ./reports
  domain-score scan example.com --aggressive
  domain-score update`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(scanCommand(), toolsCommand(), listChecksCommand(), explainCommand(), updateCommand(), versionCommand())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func scanCommand() *cobra.Command {
	flags := scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan <domain-or-url>",
		Short: "Run a domain audit for the given domain name",
		Long: `Run a public audit for one domain.

The required argument is the domain name to audit. You can pass either a bare
domain such as example.com, or a URL such as https://example.com. Domain Score
extracts the hostname and audits public DNS, TLS, HTTP, SEO, AI-readiness,
performance and transparency signals.

Default scans are safe/non-invasive. Aggressive checks run only with
--aggressive, --profile aggressive, or explicit --enable check.id.`,
		Example: `  domain-score scan example.com
  domain-score scan https://example.com --format json,md --out ./reports
  domain-score scan example.com --out - --format json
  domain-score scan example.com --details findings
  domain-score scan example.com --details-check dns.dmarc
  domain-score scan example.com --aggressive
  domain-score scan example.com --enable aggressive.port_scan`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureLatestVersion(cmd.Context()); err != nil {
				return err
			}
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
			if !report.IsSortMode(flags.sort) {
				return fmt.Errorf("unsupported sort %q; use weight, status, category, id, or none", flags.sort)
			}
			if !report.IsDetailsMode(flags.details) {
				return fmt.Errorf("unsupported details %q; use off, findings, or all", flags.details)
			}
			selectedTools, err := exttools.ExpandList(flags.tools)
			if err != nil {
				return err
			}
			if _, err := exttools.NormalizeRuntime(flags.toolRuntime); err != nil {
				return err
			}
			if _, err := exttools.NormalizePullPolicy(flags.toolsPull); err != nil {
				return err
			}
			scanTimeout := flags.timeout * time.Duration(4)
			if len(selectedTools) > 0 && flags.toolsTimeout+flags.timeout > scanTimeout {
				scanTimeout = flags.toolsTimeout + flags.timeout
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), scanTimeout)
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
				Tools: exttools.Options{
					Tools:    flags.tools,
					Runtime:  flags.toolRuntime,
					Image:    flags.toolsImage,
					Pull:     flags.toolsPull,
					Timeout:  flags.toolsTimeout,
					CacheDir: flags.toolsCacheDir,
					Version:  version,
				},
			})
			if err != nil {
				return err
			}
			if flags.detailCheck != "" && !reportHasCheck(r, flags.detailCheck) {
				return fmt.Errorf("unknown details-check %q in this scan result", flags.detailCheck)
			}
			return writeOutputs(r, flags)
		},
	}
	cmd.Flags().StringVar(&flags.format, "format", "console", "Comma-separated output formats: console,json,md")
	cmd.Flags().StringVar(&flags.out, "out", "-", "Output directory, or '-' for stdout")
	cmd.Flags().StringVar(&flags.profile, "profile", "safe", "Scan profile: safe, standard, aggressive")
	cmd.Flags().BoolVar(&flags.aggressive, "aggressive", false, "Enable all aggressive checks and evidence collectors")
	cmd.Flags().StringSliceVar(&flags.enable, "enable", nil, "Enable specific check IDs, including aggressive checks")
	cmd.Flags().StringSliceVar(&flags.disable, "disable", nil, "Disable specific check IDs")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 8*time.Second, "Per-request timeout")
	cmd.Flags().StringVar(&flags.userAgent, "user-agent", "", "Custom User-Agent")
	cmd.Flags().StringVar(&flags.weights, "weights", "", "YAML file overriding check weights: weights: {check.id: 3}")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "Disable ANSI colors in console output")
	cmd.Flags().StringVar(&flags.sort, "sort", "weight", "Sort console/markdown check rows: weight, status, category, id, none")
	cmd.Flags().StringVar(&flags.details, "details", "off", "Add detailed explanations to console/markdown output: off, findings, all")
	cmd.Flags().StringVar(&flags.detailCheck, "details-check", "", "Add detailed explanation for one specific check ID")
	cmd.Flags().StringVar(&flags.tools, "tools", "none", "External Docker tools: none, all, projectdiscovery, or comma-separated tool names")
	cmd.Flags().StringVar(&flags.toolRuntime, "tool-runtime", "docker", "External tools runtime: docker")
	cmd.Flags().StringVar(&flags.toolsImage, "tools-image", exttools.DefaultImage(version), "Docker image for external tools")
	cmd.Flags().StringVar(&flags.toolsPull, "tools-pull", "auto", "External tools image pull policy: auto, always, never")
	cmd.Flags().DurationVar(&flags.toolsTimeout, "tools-timeout", exttools.DefaultTimeout, "External tools timeout")
	cmd.Flags().StringVar(&flags.toolsCacheDir, "tools-cache-dir", "", "External tools cache directory")
	return cmd
}

func reportHasCheck(r audit.Report, checkID string) bool {
	for _, res := range r.Results {
		if res.CheckID == checkID {
			return true
		}
	}
	return false
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
			data = report.MarkdownWithOptions(r, report.MarkdownOptions{Sort: flags.sort, Details: flags.details, DetailsCheck: flags.detailCheck})
			name = "report.md"
		case "console", "text":
			data = report.Console(r, report.ConsoleOptions{Color: !flags.noColor, Sort: flags.sort, Details: flags.details, DetailsCheck: flags.detailCheck})
			name = "report.txt"
		default:
			return fmt.Errorf("unsupported format %q", f)
		}
		if err != nil {
			return err
		}
		if flags.out == "-" {
			if len(formats) > 1 {
				fmt.Printf("--- %s ---\n", name)
			}
			fmt.Print(string(data))
			if len(formats) > 1 {
				fmt.Println()
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(flags.out, name), data, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "domain-score: %s scored %d/100 (%s)\n", r.Target.Domain, r.Score.Overall, r.Score.Grade)
	return nil
}

func toolsCommand() *cobra.Command {
	var image string
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage Docker-based external audit tools",
	}
	cmd.PersistentFlags().StringVar(&image, "tools-image", exttools.DefaultImage(version), "Docker image for external tools")
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List supported external tools and aliases",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "tools:")
			for _, tool := range exttools.KnownTools {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", tool)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "\naliases:")
			fmt.Fprintln(cmd.OutOrStdout(), "  all = subfinder,httpx,naabu,nuclei,amass,testssl,zap,internetnl,greenbone")
			fmt.Fprintln(cmd.OutOrStdout(), "  projectdiscovery = subfinder,httpx,naabu,nuclei")
			fmt.Fprintln(cmd.OutOrStdout(), "  web-passive = httpx,zap")
			fmt.Fprintln(cmd.OutOrStdout(), "  tls = testssl")
			fmt.Fprintln(cmd.OutOrStdout(), "  standards = internetnl")
			fmt.Fprintln(cmd.OutOrStdout(), "  vuln = nuclei,greenbone")
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check Docker availability for external tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			if err := exttools.Doctor(ctx, "docker"); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Docker runtime OK\nTools image: %s\n", image)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "pull",
		Short: "Pull the Docker image for external tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()
			if err := exttools.Doctor(ctx, "docker"); err != nil {
				return err
			}
			if err := exttools.Pull(ctx, image); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Pulled %s\n", image)
			return nil
		},
	})
	return cmd
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

func updateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Download and install the latest GitHub Release binary",
		Long: `Download the latest matching GitHub Release asset for this OS and
architecture, verify the GitHub sha256 digest when available, extract the
domain-score binary, and replace the currently running executable.`,
		Example: `  domain-score update`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			return selfupdate.Update(ctx, selfUpdateConfig(), os.Stderr)
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

func ensureLatestVersion(ctx context.Context) error {
	if !selfupdate.IsReleaseVersion(version) {
		return nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := selfupdate.Check(checkCtx, selfUpdateConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not check latest domain-score release: %v\n", err)
		return nil
	}
	if !result.Outdated {
		return nil
	}
	return fmt.Errorf(`outdated domain-score binary

current version: %s
latest version:  %s

this release binary will not run scans until it is updated:

  domain-score update

latest release:
%s`, result.CurrentVersion, result.LatestVersion, result.LatestURL)
}

func selfUpdateConfig() selfupdate.Config {
	return selfupdate.Config{
		CurrentVersion: version,
		Client:         &http.Client{Timeout: 60 * time.Second},
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
