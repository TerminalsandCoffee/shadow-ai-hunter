# Shadow AI Hunter

Detect unauthorized AI service usage across your network. Scans proxy, DNS, and firewall logs to identify employees or systems connecting to AI services — exposing shadow AI in your organization.

## Why This Matters

Employees are using ChatGPT, Copilot, Claude, Gemini, and dozens of other AI services — often pasting proprietary code, customer data, and internal documents. Most organizations have zero visibility into this. Shadow AI Hunter gives you that visibility.

## Features

- Scans **Squid proxy logs**, **DNS query logs**, and **generic CSV/firewall logs**
- Ships with **45+ AI services** and **130+ domains** pre-loaded (LLMs, code assistants, image generators, voice AI, and more)
- Auto-detects log format or specify manually
- Reports in **table**, **JSON**, or **CSV** format
- Supports **custom domain lists** — add your own AI services to monitor
- Single binary, zero dependencies, fully offline

## Quick Start

```bash
# Build
go build -o shadow-hunter .

# Scan a single log file
./shadow-hunter -file /var/log/squid/access.log

# Scan a directory of logs
./shadow-hunter -dir /var/log/proxy/

# Specify format and output as JSON
./shadow-hunter -file firewall_export.csv -format csv -output json

# Save report to file
./shadow-hunter -file access.log -output json -out report.json

# Use custom AI service list
./shadow-hunter -file access.log -custom my_services.json
```

## Supported Log Formats

| Format | Flag | Auto-detected by |
|--------|------|------------------|
| Squid proxy | `-format squid` | Filename contains "squid", "proxy", or "access.log" |
| DNS query | `-format dns` | Filename contains "dns" or "query" |
| CSV/Firewall | `-format csv` | `.csv` file extension |

### CSV Column Mapping

The CSV parser auto-maps columns by header name (case-insensitive):

- **Timestamp**: `timestamp`, `time`, `date`, `datetime`
- **Source IP**: `source_ip`, `src_ip`, `src`, `client_ip`
- **Destination**: `destination`, `dst`, `domain`, `host`, `url`
- **Bytes**: `bytes`, `bytes_sent`, `size`
- **Action**: `action`, `status`, `status_code`

## AI Services Tracked

Covers all major categories:

- **LLMs**: OpenAI, Anthropic, Google AI, DeepSeek, Mistral, Groq, xAI, Meta AI
- **Code Assistants**: GitHub Copilot, Cursor, Tabnine, Codeium
- **Image Generation**: DALL-E, Midjourney, Stability AI, Leonardo AI
- **Video Generation**: Runway ML, Pika, Synthesia
- **Voice AI**: ElevenLabs, Murf AI
- **AI Search**: Perplexity
- **Content Gen**: Jasper AI, Copy.ai, Writesonic
- **Cloud AI**: AWS Bedrock, Azure OpenAI
- **ML Platforms**: Hugging Face, Replicate, Together AI, Fireworks AI

See `ai_services.json` for the full list. Add your own with `-custom`.

## Custom Domain Lists

Create a JSON file with the same structure as `ai_services.json`:

```json
{
  "services": [
    {
      "name": "Internal AI Tool",
      "category": "Internal",
      "domains": ["ai.internal.corp", "llm-proxy.internal.corp"]
    }
  ]
}
```

Then pass it with `-custom my_services.json`.

## CLI Options

```
  -file string      Path to log file to scan
  -dir string       Path to directory of log files to scan
  -format string    Log format: squid, dns, csv, auto (default "auto")
  -output string    Output format: table, json, csv (default "table")
  -out string       Write report to file instead of stdout
  -services string  Path to AI services JSON (default: bundled ai_services.json)
  -custom string    Path to additional custom AI services JSON
  -quiet            Suppress banner
  -version          Show version
```

## Sample Output

```
  SHADOW AI HUNTER - Scan Results
============================================================
  Logs scanned:    25
  AI hits found:   16
  Unique users:    12
  Unique services: 11
============================================================

  TOP USERS BY AI SERVICE HITS
----------------------------------------
  192.168.1.50    5 hits
  192.168.1.51    2 hits
  192.168.1.54    2 hits

  TOP AI SERVICES DETECTED
----------------------------------------
  OpenAI          5 hits
  Anthropic       2 hits
  Google AI       1 hits
  Mistral AI      1 hits
```

## Building

```bash
# Build for current platform
go build -o shadow-hunter .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o shadow-hunter-linux .

# Cross-compile for macOS
GOOS=darwin GOARCH=arm64 go build -o shadow-hunter-mac .
```

## License

MIT
