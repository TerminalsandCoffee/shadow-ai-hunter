package parsers

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// CSVParser handles generic CSV/firewall logs.
// Expected columns (case-insensitive header matching):
//
//	timestamp, source_ip (or src_ip), destination (or dst, domain, host, url),
//	action (optional), bytes (optional), protocol (optional)
type CSVParser struct{}

func (p *CSVParser) Name() string {
	return "csv"
}

func (p *CSVParser) Parse(filepath string) ([]LogEntry, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", filepath, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	reader.LazyQuotes = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing CSV %s: %w", filepath, err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV has no data rows")
	}

	// Map column names to indices
	colMap := mapColumns(records[0])

	tsCol := findCol(colMap, "timestamp", "time", "date", "datetime")
	srcCol := findCol(colMap, "source_ip", "src_ip", "src", "client_ip", "source")
	dstCol := findCol(colMap, "destination", "dst", "domain", "host", "url", "dest", "dst_host")
	bytesCol := findCol(colMap, "bytes", "bytes_sent", "size", "content_length")
	actionCol := findCol(colMap, "action", "status", "status_code", "result")

	if dstCol == -1 {
		return nil, fmt.Errorf("CSV missing required destination/domain column")
	}

	var entries []LogEntry
	for _, row := range records[1:] {
		entry := LogEntry{RawLine: strings.Join(row, ",")}

		if tsCol >= 0 && tsCol < len(row) {
			entry.Timestamp = parseFlexibleTime(row[tsCol])
		}
		if srcCol >= 0 && srcCol < len(row) {
			entry.SourceIP = strings.TrimSpace(row[srcCol])
		}
		if dstCol >= 0 && dstCol < len(row) {
			val := strings.TrimSpace(row[dstCol])
			entry.Domain = strings.ToLower(val)
			// If it looks like a URL, extract domain
			if strings.Contains(val, "://") {
				entry.URL = val
				entry.Domain = extractDomain(val)
			}
		}
		if bytesCol >= 0 && bytesCol < len(row) {
			entry.BytesSent, _ = strconv.ParseInt(strings.TrimSpace(row[bytesCol]), 10, 64)
		}
		if actionCol >= 0 && actionCol < len(row) {
			entry.StatusCode = strings.TrimSpace(row[actionCol])
		}

		if entry.Domain != "" {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func mapColumns(header []string) map[string]int {
	m := make(map[string]int)
	for i, col := range header {
		m[strings.ToLower(strings.TrimSpace(col))] = i
	}
	return m
}

func findCol(colMap map[string]int, names ...string) int {
	for _, name := range names {
		if idx, ok := colMap[name]; ok {
			return idx
		}
	}
	return -1
}

// parseFlexibleTime tries multiple common timestamp formats.
func parseFlexibleTime(s string) time.Time {
	s = strings.TrimSpace(s)
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"01/02/2006 15:04:05",
		"02/Jan/2006:15:04:05 -0700",
		"Jan 2 15:04:05 2006",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
