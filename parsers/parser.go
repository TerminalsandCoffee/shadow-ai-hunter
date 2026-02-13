package parsers

import "time"

// LogEntry is the normalized format all parsers produce.
type LogEntry struct {
	Timestamp   time.Time
	SourceIP    string
	Domain      string // destination domain or hostname
	URL         string // full URL if available
	Method      string // HTTP method if available
	StatusCode  string
	BytesSent   int64
	RawLine     string
}

// Parser is the interface every log format must implement.
type Parser interface {
	Name() string
	Parse(filepath string) ([]LogEntry, error)
}
