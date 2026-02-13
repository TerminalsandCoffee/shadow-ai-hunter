package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/shadow-ai-hunter/analyzer"
)

// Format specifies the output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
)

// Report outputs the analysis summary in the requested format.
func Report(summary analyzer.Summary, format Format, w io.Writer) error {
	switch format {
	case FormatTable:
		return reportTable(summary, w)
	case FormatJSON:
		return reportJSON(summary, w)
	case FormatCSV:
		return reportCSV(summary, w)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

// WriteToFile writes the report to a file instead of stdout.
func WriteToFile(summary analyzer.Summary, format Format, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()
	return Report(summary, format, f)
}

func reportTable(s analyzer.Summary, w io.Writer) error {
	// Header banner
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  SHADOW AI HUNTER - Scan Results")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintf(w, "  Logs scanned:    %d\n", s.TotalLogsScanned)
	fmt.Fprintf(w, "  AI hits found:   %d\n", s.TotalFindings)
	fmt.Fprintf(w, "  Unique users:    %d\n", s.UniqueUsers)
	fmt.Fprintf(w, "  Unique services: %d\n", s.UniqueServices)
	fmt.Fprintln(w, strings.Repeat("=", 60))

	if s.TotalFindings == 0 {
		fmt.Fprintln(w, "\n  No shadow AI activity detected.")
		return nil
	}

	// Top users
	fmt.Fprintln(w, "\n  TOP USERS BY AI SERVICE HITS")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, kv := range sortedMap(s.ByUser) {
		fmt.Fprintf(tw, "  %s\t%d hits\n", kv.key, kv.val)
	}
	tw.Flush()

	// Top services
	fmt.Fprintln(w, "\n  TOP AI SERVICES DETECTED")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	tw = tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, kv := range sortedMap(s.ByService) {
		fmt.Fprintf(tw, "  %s\t%d hits\n", kv.key, kv.val)
	}
	tw.Flush()

	// Detailed findings
	fmt.Fprintln(w, "\n  DETAILED FINDINGS")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	tw = tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  TIMESTAMP\tSOURCE IP\tSERVICE\tCATEGORY\tDOMAIN\n")
	fmt.Fprintf(tw, "  ---------\t---------\t-------\t--------\t------\n")
	for _, f := range s.Findings {
		ts := f.Timestamp.Format("2006-01-02 15:04:05")
		if f.Timestamp.IsZero() {
			ts = "N/A"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			ts, f.SourceIP, f.ServiceName, f.Category, f.Domain)
	}
	tw.Flush()
	fmt.Fprintln(w)

	return nil
}

// jsonReport mirrors the summary for clean JSON output.
type jsonReport struct {
	TotalLogsScanned int               `json:"total_logs_scanned"`
	TotalFindings    int               `json:"total_findings"`
	UniqueUsers      int               `json:"unique_users"`
	UniqueServices   int               `json:"unique_services"`
	ByUser           map[string]int    `json:"hits_by_user"`
	ByService        map[string]int    `json:"hits_by_service"`
	Findings         []jsonFinding     `json:"findings"`
}

type jsonFinding struct {
	Timestamp   string `json:"timestamp"`
	SourceIP    string `json:"source_ip"`
	ServiceName string `json:"service_name"`
	Category    string `json:"category"`
	Domain      string `json:"domain"`
	URL         string `json:"url,omitempty"`
	Method      string `json:"method,omitempty"`
	StatusCode  string `json:"status_code,omitempty"`
	BytesSent   int64  `json:"bytes_sent,omitempty"`
}

func reportJSON(s analyzer.Summary, w io.Writer) error {
	report := jsonReport{
		TotalLogsScanned: s.TotalLogsScanned,
		TotalFindings:    s.TotalFindings,
		UniqueUsers:      s.UniqueUsers,
		UniqueServices:   s.UniqueServices,
		ByUser:           s.ByUser,
		ByService:        s.ByService,
	}

	for _, f := range s.Findings {
		ts := ""
		if !f.Timestamp.IsZero() {
			ts = f.Timestamp.Format("2006-01-02T15:04:05Z")
		}
		report.Findings = append(report.Findings, jsonFinding{
			Timestamp:   ts,
			SourceIP:    f.SourceIP,
			ServiceName: f.ServiceName,
			Category:    f.Category,
			Domain:      f.Domain,
			URL:         f.URL,
			Method:      f.Method,
			StatusCode:  f.StatusCode,
			BytesSent:   f.BytesSent,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func reportCSV(s analyzer.Summary, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{"timestamp", "source_ip", "service_name", "category", "domain", "url", "method", "status_code", "bytes_sent"}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, f := range s.Findings {
		ts := ""
		if !f.Timestamp.IsZero() {
			ts = f.Timestamp.Format("2006-01-02T15:04:05Z")
		}
		row := []string{
			ts,
			f.SourceIP,
			f.ServiceName,
			f.Category,
			f.Domain,
			f.URL,
			f.Method,
			f.StatusCode,
			fmt.Sprintf("%d", f.BytesSent),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return nil
}

type kv struct {
	key string
	val int
}

func sortedMap(m map[string]int) []kv {
	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].val > sorted[j].val
	})
	return sorted
}
