package parsers

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// DNSParser handles common DNS query log formats.
// Supports two formats:
//   1. Simple: timestamp client_ip query_domain query_type
//      Example: 2025-06-10T08:30:00Z 192.168.1.50 api.openai.com A
//   2. Dnsmasq-style: Mon Jun 10 08:30:00 2025 query[A] api.openai.com from 192.168.1.50
type DNSParser struct{}

func (p *DNSParser) Name() string {
	return "dns"
}

func (p *DNSParser) Parse(filepath string) ([]LogEntry, error) {
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

		// Try simple format first, then dnsmasq
		entry, err := parseSimpleDNS(line)
		if err != nil {
			entry, err = parseDnsmasq(line)
		}
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath, err)
	}

	return entries, nil
}

// parseSimpleDNS parses: 2025-06-10T08:30:00Z 192.168.1.50 api.openai.com A
func parseSimpleDNS(line string) (LogEntry, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return LogEntry{}, fmt.Errorf("not enough fields")
	}

	ts, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return LogEntry{}, fmt.Errorf("bad timestamp: %w", err)
	}

	return LogEntry{
		Timestamp: ts,
		SourceIP:  fields[1],
		Domain:    strings.ToLower(strings.TrimSuffix(fields[2], ".")),
		RawLine:   line,
	}, nil
}

// parseDnsmasq parses: Jun 10 08:30:00 dnsmasq[1234]: query[A] api.openai.com from 192.168.1.50
func parseDnsmasq(line string) (LogEntry, error) {
	// Look for "query[" as a marker
	qIdx := strings.Index(line, "query[")
	if qIdx == -1 {
		return LogEntry{}, fmt.Errorf("not a dnsmasq query line")
	}

	// Extract the part after "query[X] "
	afterQuery := line[qIdx:]
	closeBracket := strings.Index(afterQuery, "] ")
	if closeBracket == -1 {
		return LogEntry{}, fmt.Errorf("malformed query field")
	}

	rest := afterQuery[closeBracket+2:]
	parts := strings.Fields(rest)
	if len(parts) < 3 || parts[1] != "from" {
		return LogEntry{}, fmt.Errorf("unexpected format after domain")
	}

	domain := strings.ToLower(strings.TrimSuffix(parts[0], "."))
	sourceIP := parts[2]

	// Try parsing the timestamp from the beginning (syslog-style)
	// Format: "Jun 10 08:30:00"
	tsPart := strings.TrimSpace(line[:qIdx])
	// Strip hostname if present (e.g., "Jun 10 08:30:00 myhost dnsmasq[1234]:")
	// Find the dnsmasq marker and take everything before the hostname
	dnsmasqIdx := strings.Index(tsPart, "dnsmasq")
	if dnsmasqIdx > 0 {
		tsPart = strings.TrimSpace(tsPart[:dnsmasqIdx])
		// Remove trailing hostname
		tsFields := strings.Fields(tsPart)
		if len(tsFields) >= 4 {
			// Has hostname: "Jun 10 08:30:00 hostname"
			tsPart = strings.Join(tsFields[:3], " ")
		}
	}

	ts, err := time.Parse("Jan 2 15:04:05", tsPart)
	if err != nil {
		ts = time.Time{} // use zero time if unparseable
	} else {
		ts = ts.AddDate(time.Now().Year(), 0, 0)
	}

	return LogEntry{
		Timestamp: ts,
		SourceIP:  sourceIP,
		Domain:    domain,
		RawLine:   line,
	}, nil
}
