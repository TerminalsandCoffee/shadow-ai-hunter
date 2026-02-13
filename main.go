package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shadow-ai-hunter/analyzer"
	"github.com/shadow-ai-hunter/parsers"
	"github.com/shadow-ai-hunter/reporter"
)

const version = "1.0.0"

const banner = `
 _____ _               _                   ___  _____   _   _             _
/  ___| |             | |                 / _ \|_   _| | | | |           | |
\ ` + "`" + `--.| |__   __ _  __| | _____      __  / /_\ \ | |   | |_| |_   _ _ __ | |_ ___ _ __
 ` + "`" + `--. \ '_ \ / _` + "`" + ` |/ _` + "`" + ` |/ _ \ \ /\ / /  |  _  | | |   |  _  | | | | '_ \| __/ _ \ '__|
/\__/ / | | | (_| | (_| | (_) \ V  V /   | | | |_| |_  | | | | |_| | | | | ||  __/ |
\____/|_| |_|\__,_|\__,_|\___/ \_/\_/    \_| |_/\___/  \_| |_/\__,_|_| |_|\__\___|_|

  Shadow AI Hunter v%s — Detect unauthorized AI service usage
  https://github.com/shadow-ai-hunter
`

func main() {
	// CLI flags
	logFile := flag.String("file", "", "Path to log file to scan")
	logDir := flag.String("dir", "", "Path to directory of log files to scan")
	logFormat := flag.String("format", "auto", "Log format: squid, dns, csv, auto (default: auto)")
	outputFmt := flag.String("output", "table", "Output format: table, json, csv (default: table)")
	outputFile := flag.String("out", "", "Write report to file instead of stdout")
	servicesDB := flag.String("services", "", "Path to AI services JSON (default: bundled ai_services.json)")
	customDB := flag.String("custom", "", "Path to additional custom AI services JSON to merge in")
	showVersion := flag.Bool("version", false, "Show version")
	quiet := flag.Bool("quiet", false, "Suppress banner")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, banner, version)
		fmt.Fprintf(os.Stderr, "\nUsage:\n")
		fmt.Fprintf(os.Stderr, "  shadow-hunter -file <logfile> [options]\n")
		fmt.Fprintf(os.Stderr, "  shadow-hunter -dir <logdir> [options]\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  shadow-hunter -file /var/log/squid/access.log\n")
		fmt.Fprintf(os.Stderr, "  shadow-hunter -dir /var/log/proxy/ -format squid -output json\n")
		fmt.Fprintf(os.Stderr, "  shadow-hunter -file firewall.csv -format csv -out report.json -output json\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("shadow-hunter v%s\n", version)
		os.Exit(0)
	}

	if *logFile == "" && *logDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, banner, version)
	}

	// Resolve services DB path
	svcPath := *servicesDB
	if svcPath == "" {
		// Look for ai_services.json next to the binary
		exe, err := os.Executable()
		if err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "ai_services.json")
			if _, err := os.Stat(candidate); err == nil {
				svcPath = candidate
			}
		}
		// Fallback: current directory
		if svcPath == "" {
			svcPath = "ai_services.json"
		}
	}

	// Initialize analyzer
	az, err := analyzer.New(svcPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error loading AI services database: %v\n", err)
		os.Exit(1)
	}

	if *customDB != "" {
		if err := az.LoadCustomDomains(*customDB); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error loading custom domains: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "[*] Loaded %d AI services (%d domains)\n", az.ServiceCount(), az.DomainCount())

	// Collect log files to scan
	var files []string
	if *logFile != "" {
		files = append(files, *logFile)
	}
	if *logDir != "" {
		dirFiles, err := collectFiles(*logDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error reading directory: %v\n", err)
			os.Exit(1)
		}
		files = append(files, dirFiles...)
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No log files found to scan.")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[*] Scanning %d file(s)...\n", len(files))

	// Parse all files
	var allEntries []parsers.LogEntry
	for _, f := range files {
		p := selectParser(*logFormat, f)
		if p == nil {
			fmt.Fprintf(os.Stderr, "[!] Skipping %s — could not determine format\n", f)
			continue
		}
		fmt.Fprintf(os.Stderr, "[*] Parsing %s (%s format)\n", f, p.Name())

		entries, err := p.Parse(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error parsing %s: %v\n", f, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "    -> %d entries parsed\n", len(entries))
		allEntries = append(allEntries, entries...)
	}

	// Analyze
	fmt.Fprintln(os.Stderr, "[*] Analyzing for shadow AI activity...")
	summary := az.Analyze(allEntries)

	// Report
	outFmt := reporter.Format(strings.ToLower(*outputFmt))
	if *outputFile != "" {
		if err := reporter.WriteToFile(summary, outFmt, *outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error writing report: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[+] Report written to %s\n", *outputFile)
	} else {
		if err := reporter.Report(summary, outFmt, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error generating report: %v\n", err)
			os.Exit(1)
		}
	}

	if summary.TotalFindings > 0 {
		fmt.Fprintf(os.Stderr, "[!] ALERT: %d shadow AI connections detected from %d unique users\n",
			summary.TotalFindings, summary.UniqueUsers)
	} else {
		fmt.Fprintln(os.Stderr, "[+] No shadow AI activity detected. Clean scan.")
	}
}

func selectParser(format, filepath string) parsers.Parser {
	switch strings.ToLower(format) {
	case "squid":
		return &parsers.SquidParser{}
	case "dns":
		return &parsers.DNSParser{}
	case "csv":
		return &parsers.CSVParser{}
	case "auto":
		return autoDetect(filepath)
	default:
		return autoDetect(filepath)
	}
}

// autoDetect guesses the parser based on file extension and name.
func autoDetect(path string) parsers.Parser {
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	if ext == ".csv" {
		return &parsers.CSVParser{}
	}
	if strings.Contains(base, "dns") || strings.Contains(base, "query") || strings.Contains(base, "dnsmasq") {
		return &parsers.DNSParser{}
	}
	if strings.Contains(base, "squid") || strings.Contains(base, "proxy") || strings.Contains(lower, "access.log") {
		return &parsers.SquidParser{}
	}

	// Default to squid (most common proxy log format)
	return &parsers.SquidParser{}
}

func collectFiles(dir string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	return files, nil
}
