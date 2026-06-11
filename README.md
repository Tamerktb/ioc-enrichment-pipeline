# IOC Enrichment Pipeline

**Automated indicator enrichment for SOC analysts — reduce manual lookup time by ~80%.**

A production-grade pipeline that ingests raw indicators of compromise (IPs, domains, file hashes, URLs), enriches them across multiple threat intelligence APIs, caches results, computes risk scores, and outputs structured reports ready for SIEM ingestion.

```
Raw IOC (IP/domain/hash/URL)
        │
        ▼
┌──────────────────┐
│   IOC Parser      │  Parse & validate input formats
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Cache Check     │  SQLite cache — skip already-seen IOCs
└────────┬─────────┘
         │ (miss)
         ▼
┌──────────────────┐
│  Enrichment       │  Parallel lookup across configured tools
│  Manager          │  (VirusTotal, AbuseIPDB, ipinfo, Shodan...)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Cache Store      │  Write results back to cache with TTL
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Scoring Engine   │  Weighted risk score (0–10) per IOC
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  LLM Summarizer   │  Optional: natural-language threat summary
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Output           │  JSON / Splunk KV / Human-readable table
│  Formatter        │
└──────────────────┘
```

## Why This Exists

Security analysts spend **4+ hours a day** manually looking up IOCs across VirusTotal, Shodan, AbuseIPDB, and other threat intel sources. This is repetitive, error-prone, and burns analyst time that should go toward actual investigation and response.

This pipeline **automates the grunt work** — paste an IOC once, get a complete enrichment report in seconds with a risk score and optional LLM-generated summary.

## What It Demonstrates

| Engineering Skill | How It Appears in This Project |
|---|---|
| **System Design** | Modular pipeline architecture — parser, cache, enrichment workers, scoring engine, output formatters — each component is independent and swappable |
| **Tool & Contract Design** | Each enrichment tool has a strictly typed input schema with validation — the pipeline won't call an API without valid parameters |
| **Retrieval Engineering** | Cache layer with TTL per IOC type, plus optional RAG-style retrieval of past enrichment context |
| **Reliability Engineering** | Retry with exponential backoff, timeout per API call, dead-letter logging for failed enrichments, graceful degradation when APIs are down |
| **Security & Safety** | Input validation on raw IOCs, output filtering, API key isolation in `.env`, the LLM is a *summarizer* not a decision-maker |
| **Evaluation & Observability** | Every enrichment is traced (latency, cache hit/miss, tool, result); full replay trace per IOC; Splunk-compatible logs |
| **Product Thinking** | Confidence scores, clear error messages, human-readable summaries, graceful fallbacks when data is missing |

## Quick Start

### Prerequisites
- Python 3.10+
- API keys (optional — ipinfo.io works without one for basic lookups)

### Installation

```bash
# Clone or navigate to the project directory
cd "D:\IOC Enrichment Pipeline"

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys (optional — skip for limited demo)
```

### Usage

```bash
# Enrich a single IOC
python main.py enrich --type ip --value 8.8.8.8

# Enrich from a CSV file
python main.py enrich --file tests/sample_iocs.csv

# Enrich from JSON
python main.py enrich --file tests/sample_iocs.json

# Output in Splunk-compatible format
python main.py enrich --type ip --value 185.130.5.173 --format splunk

# Enable LLM threat summary
python main.py enrich --type ip --value 185.130.5.173 --llm-summary

# List available enrichment tools
python main.py tools

# Check cache status
python main.py cache-stats
```

### Output Formats

- **json** (default): Full structured report — enrichment data, score, timestamps, tool metadata
- **splunk**: Key-value pair format ready for SIEM ingestion
- **table**: Human-readable Rich terminal table

## Project Structure

```
├── main.py                  # CLI entry point
├── config.yaml              # Global configuration
├── .env                     # API keys (gitignored)
├── requirements.txt
├── README.md
├── pipeline/
│   ├── orchestrator.py      # Main pipeline orchestrator
│   ├── ioc_parser.py        # IOC parsing & validation
│   ├── cache.py             # SQLite cache layer
│   ├── scoring.py           # Risk scoring engine
│   ├── output.py            # Output formatters
│   ├── llm_summarizer.py    # Optional LLM-based summarizer
│   └── tools/
│       ├── base.py          # Abstract base tool with typed schema
│       ├── ipinfo.py        # IP geolocation (no key required)
│       ├── abuseipdb.py     # AbuseIPDB reputation
│       ├── virustotal.py    # VirusTotal lookups
│       └── manager.py       # Parallel enrichment manager
├── tests/
│   ├── sample_iocs.csv
│   └── sample_iocs.json
└── output/                  # Generated reports (gitignored)
```

## Configuration

All settings in `config.yaml`:

```yaml
cache:
  path: pipeline_cache.db     # SQLite cache file
  default_ttl: 3600           # Default TTL in seconds
  ttl_by_type:
    ip: 3600                  # 1 hour
    domain: 7200              # 2 hours
    hash: 86400               # 24 hours

enrichment:
  timeout: 15                 # Per-API timeout
  max_retries: 3              # Retry attempts
  retry_delay: 2             # Base delay in seconds
  parallel: true              # Run tools concurrently

scoring:
  weights:
    malicious_reports: 0.35
    source_count: 0.20
    abuse_reports: 0.25
    geo_risk: 0.10
    freshness: 0.10

llm:
  provider: openrouter        # or openai
  model: openai/gpt-4o-mini   # Model name
  max_tokens: 300
  temperature: 0.3
```

## API Keys

| Service | Required? | Free Tier | Get Key |
|---|---|---|---|
| ipinfo.io | **No** | 50k req/month | Not needed |
| AbuseIPDB | Optional | 1k req/day | https://www.abuseipdb.com/api |
| VirusTotal | Optional | 4 req/min, 500/day | https://www.virustotal.com/gui/my-apikey |

Without any API keys, the pipeline still works with ipinfo.io for geolocation and demonstrates the full architecture.

## License

MIT