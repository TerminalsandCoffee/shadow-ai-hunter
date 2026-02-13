package parsers

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// SquidParser handles Squid proxy access.log format.
// Format: timestamp elapsed client action/code size method URL ident hierarchy/from content-type
// Example: 1718000000.000    200 192.168.1.50 TCP_MISS/200 1500 GET https://api.openai.com/v1/chat/completions - DIRECT/api.openai.com text/html
type SquidParser struct{}

func (p *SquidParser) Name() string {
	return "squid"
}

func (p *SquidParser) Parse(filepath string) ([]LogEntry, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", filepath, err)
	}
	defer file.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseSquidLine(line)
		if err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath, err)
	}

	return entries, nil
}

func parseSquidLine(line string) (LogEntry, error) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return LogEntry{}, fmt.Errorf("not enough fields")
	}

	// Parse unix timestamp (e.g., 1718000000.000)
	tsFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return LogEntry{}, fmt.Errorf("bad timestamp: %w", err)
	}
	ts := time.Unix(int64(tsFloat), 0).UTC()

	// Source IP is field 2
	sourceIP := fields[2]

	// Action/status code is field 3 (e.g., TCP_MISS/200)
	statusCode := ""
	if parts := strings.SplitN(fields[3], "/", 2); len(parts) == 2 {
		statusCode = parts[1]
	}

	// Bytes is field 4
	bytesSent, _ := strconv.ParseInt(fields[4], 10, 64)

	// Method is field 5
	method := fields[5]

	// URL is field 6
	rawURL := fields[6]

	// Extract domain from URL
	domain := extractDomain(rawURL)

	return LogEntry{
		Timestamp:  ts,
		SourceIP:   sourceIP,
		Domain:     domain,
		URL:        rawURL,
		Method:     method,
		StatusCode: statusCode,
		BytesSent:  bytesSent,
		RawLine:    line,
	}, nil
}

func extractDomain(rawURL string) string {
	// Handle CONNECT method URLs (just host:port)
	if !strings.Contains(rawURL, "://") {
		host := strings.SplitN(rawURL, ":", 2)[0]
		return strings.ToLower(host)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	host := parsed.Hostname()
	return strings.ToLower(host)
}
