package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shadow-ai-hunter/parsers"
)

// AIService represents a known AI service from the database.
type AIService struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Domains  []string `json:"domains"`
}

type servicesFile struct {
	Services []AIService `json:"services"`
}

// Finding is a single matched event — a log entry that hit an AI service.
type Finding struct {
	Timestamp   time.Time
	SourceIP    string
	ServiceName string
	Category    string
	Domain      string
	URL         string
	Method      string
	StatusCode  string
	BytesSent   int64
}

// Summary aggregates findings for reporting.
type Summary struct {
	TotalLogsScanned int
	TotalFindings    int
	UniqueUsers      int
	UniqueServices   int
	Findings         []Finding
	ByUser           map[string]int // source_ip -> hit count
	ByService        map[string]int // service name -> hit count
}

// Analyzer matches log entries against known AI service domains.
type Analyzer struct {
	domainMap map[string]AIService // domain -> service
}

// New creates an Analyzer loaded with AI services from a JSON file.
func New(servicesPath string) (*Analyzer, error) {
	data, err := os.ReadFile(servicesPath)
	if err != nil {
		return nil, fmt.Errorf("reading services file: %w", err)
	}

	var sf servicesFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parsing services file: %w", err)
	}

	a := &Analyzer{
		domainMap: make(map[string]AIService),
	}

	for _, svc := range sf.Services {
		for _, domain := range svc.Domains {
			a.domainMap[strings.ToLower(domain)] = svc
		}
	}

	return a, nil
}

// LoadCustomDomains merges additional domains from a user-provided JSON file.
func (a *Analyzer) LoadCustomDomains(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading custom domains: %w", err)
	}

	var sf servicesFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("parsing custom domains: %w", err)
	}

	for _, svc := range sf.Services {
		for _, domain := range svc.Domains {
			a.domainMap[strings.ToLower(domain)] = svc
		}
	}
	return nil
}

// Analyze checks a slice of log entries against known AI domains.
func (a *Analyzer) Analyze(entries []parsers.LogEntry) Summary {
	summary := Summary{
		TotalLogsScanned: len(entries),
		ByUser:           make(map[string]int),
		ByService:        make(map[string]int),
	}

	for _, entry := range entries {
		svc, found := a.matchDomain(entry.Domain)
		if !found {
			continue
		}

		finding := Finding{
			Timestamp:   entry.Timestamp,
			SourceIP:    entry.SourceIP,
			ServiceName: svc.Name,
			Category:    svc.Category,
			Domain:      entry.Domain,
			URL:         entry.URL,
			Method:      entry.Method,
			StatusCode:  entry.StatusCode,
			BytesSent:   entry.BytesSent,
		}

		summary.Findings = append(summary.Findings, finding)
		summary.ByUser[entry.SourceIP]++
		summary.ByService[svc.Name]++
	}

	summary.TotalFindings = len(summary.Findings)
	summary.UniqueUsers = len(summary.ByUser)
	summary.UniqueServices = len(summary.ByService)

	return summary
}

// ServiceCount returns how many AI services are loaded.
func (a *Analyzer) ServiceCount() int {
	seen := make(map[string]bool)
	for _, svc := range a.domainMap {
		seen[svc.Name] = true
	}
	return len(seen)
}

// DomainCount returns how many domains are being watched.
func (a *Analyzer) DomainCount() int {
	return len(a.domainMap)
}

// matchDomain checks if a domain (or any parent domain) matches a known AI service.
func (a *Analyzer) matchDomain(domain string) (AIService, bool) {
	domain = strings.ToLower(domain)

	// Exact match
	if svc, ok := a.domainMap[domain]; ok {
		return svc, true
	}

	// Subdomain matching: try stripping subdomains progressively
	// e.g., "foo.api.openai.com" -> "api.openai.com" -> "openai.com"
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if svc, ok := a.domainMap[parent]; ok {
			return svc, true
		}
	}

	return AIService{}, false
}
