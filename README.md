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

## Quick Start (Web UI)

### 3 steps — works no matter where you cloned it

**Step 1** — Open a terminal in the project folder:

```
Windows:  Right-click the project folder → "Open in Terminal"
          Or: Win + R → cmd → cd \path\to\ioc-enrichment-pipeline

Mac/Linux: cd /path/to/ioc-enrichment-pipeline
```

**Step 2** — Install and launch (one command):

```bash
pip install -r requirements.txt streamlit && streamlit run app.py
```

Wait ~15 seconds. You'll see:

```
  You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
```

**Step 3** — Open **http://localhost:8501** in your browser.

### How to use the Web UI

The interface is self-explanatory — here's what you'll see:

1. **A search box** — paste any IP address, domain, or file hash
2. **Example buttons** — click one to try it instantly (no typing needed)
3. **"Look Up" button** — click it and results appear in under a second

**What you get back:**

```
┌──────────────────────────────────────────────────────┐
│  IP                            ┌─────────┐          │
│  8.8.8.8                       │   LOW   │          │
│  Source: manual · ⏱ 0.37s     │  3.97   │          │
│                                │ out of 10│          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │📍Location│ │🌐 ISP    │ │🔢 ASN   │ │🏳️Country│ │
│  │Mountain  │ │Google LLC│ │AS15169  │ │US       │ │
│  │View, CA  │ │          │ │         │ │         │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘ │
└──────────────────────────────────────────────────────┘
```

- **Risk score** (0–10) with color-coded severity badge
- **Location, ISP, ASN, country** — all in a clean card
- **"View raw data"** expander — for power users who want the full JSON

**Batch upload:** Click "Upload a file" at the bottom to process a CSV with multiple indicators at once.

### (Optional) Add API keys for more data

The pipeline works without any keys — ipinfo.io is free and requires no sign-up.  
To unlock VirusTotal and AbuseIPDB, get free keys and add them:

1. Copy the template: `cp .env.example .env`
2. Edit `.env` and paste your keys
3. Free keys at: [VirusTotal](https://www.virustotal.com/gui/my-apikey) | [AbuseIPDB](https://www.abuseipdb.com/api)

### Advanced: CLI usage

If you prefer the terminal, the CLI is also available:

```bash
# Enrich a single IOC
python main.py enrich --type ip --value 8.8.8.8 --format table

# Enrich from a CSV file
python main.py enrich --file tests/sample_iocs.csv

# Output in Splunk-compatible format (for SIEM ingestion)
python main.py enrich --type ip --value 185.130.5.173 --format splunk

# View available tools
python main.py tools
```

**Output formats (CLI only):** `json` (default), `splunk`, `table`

## Project Structure

```
├── main.py                  # CLI entry point
├── app.py                   # Streamlit web UI (http://localhost:8501)
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