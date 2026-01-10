# Recon Suite

**Phased reconnaissance framework for bug bounty hunting.**

Built for hunters who want control, not just automation.

---

## Philosophy

- **Phased, not monolithic** - Each phase produces files that feed the next. You control when to proceed.
- **Scope is sacred** - Every phase enforces scope. Out-of-scope assets are filtered or flagged.
- **Analysis over enumeration** - Finding 50,000 subdomains means nothing. Understanding 500 interesting ones means everything.
- **Custom where it matters** - Wrap battle-tested tools for commodity tasks. Build custom for analytical tasks.

---

## Architecture

```
Phase 1: Passive Subdomain Enumeration    ✅ DONE
         Output: subdomains.csv
              ↓
Phase 2: Resolution & Filtering           ✅ DONE
         Input: subdomains.csv
         Output: live_hosts.csv, dead_hosts.csv, ip_groups.csv
              ↓
Phase 3: Content Discovery                🔄 PLANNED
         Input: live_hosts.csv
         Output: js_findings.csv, wayback_findings.csv, endpoints.csv
              ↓
Phase 4: Analysis                         🔄 PLANNED
         Input: live_hosts.csv + endpoints.csv
         Output: reflection_map.csv, error_analysis.csv, auth_flows.csv
              ↓
Phase 5: Vulnerability Checks             🔄 PLANNED
         Input: dead_hosts.csv + live_hosts.csv
         Output: takeover_results.csv, misconfig_results.csv
```

---

## Quick Start

### 1. Setup Project

```bash
# Clone repository
git clone <repo-url>
cd recon-suite

# Create project directory for your target
mkdir -p projects/target-corp
cd projects/target-corp

# Copy configuration templates
cp ../../scope.json.example scope.json
cp ../../config.json.example config.json

# Edit scope.json with your target's scope
# Edit config.json if you need custom settings
```

### 2. Define Scope

Edit `scope.json`:

```json
{
  "name": "Target Corp Bug Bounty",
  "in_scope": [
    "*.target.com",
    "*.target.io"
  ],
  "out_of_scope": [
    "support.target.com",
    "status.target.com"
  ]
}
```

### 3. Run Phase 1: Passive Enumeration

```bash
# Create input domains file
mkdir -p input
echo "target.com" > input/domains.txt
echo "target.io" >> input/domains.txt

# Copy Phase 1 config
cp ../../passive-recon/config.json.example passive-recon-config.json
# Edit with your API tokens

# Run Phase 1
python ../../passive-recon/master_enum.py passive-recon-config.json
```

### 4. Run Phase 2: Resolution

```bash
# Run Phase 2 on Phase 1 results
python ../../resolution/resolver_main.py \
    --input output/final_results.csv \
    --scope scope.json \
    --output-dir phase2-resolution
```

### 5. Review Results

```
phase2-resolution/
├── live_hosts.csv      # Your main targets - hosts that responded
├── dead_hosts.csv      # Takeover candidates - didn't respond
├── ip_groups.csv       # Subdomains sharing same IP
└── metadata.json       # Statistics
```

---

## Phase Details

### Phase 1: Passive Subdomain Enumeration ✅

**Tools integrated:**
- Microsoft Threat Intelligence (native API)
- SecurityTrails (native API)  
- crt.sh (Certificate Transparency)
- Sublist3r (Search engine aggregation)

**Key features:**
- Multi-token/cookie rotation
- Smart deduplication with confidence scoring
- Checkpoint/resume capability

**Output:** `subdomains.csv` with source tracking and confidence scores

See [passive-recon/README.md](passive-recon/README.md) for detailed setup.

---

### Phase 2: Resolution & Filtering ✅

**Purpose:** Filter passive results to live hosts, remove noise.

**Components:**
- **httpx wrapper** - Probes all subdomains, captures response metadata
- **IP grouper** - Groups subdomains by resolved IP (shared infrastructure detection)
- **Scope filter** - Enforces in-scope/out-of-scope rules

**Usage:**

```bash
python resolution/resolver_main.py \
    --input phase1-passive/subdomains.csv \
    --scope scope.json \
    --output-dir phase2-resolution \
    --config config.json  # optional
```

**Options:**

| Flag | Description |
|------|-------------|
| `-i, --input` | Phase 1 CSV file (required) |
| `-s, --scope` | scope.json file (required) |
| `-o, --output-dir` | Output directory (default: ./phase2-resolution) |
| `-c, --config` | config.json for httpx settings |
| `--subdomain-column` | CSV column name (default: subdomain) |
| `--skip-scope-filter` | Process all subdomains regardless of scope |

**Output files:**

| File | Description |
|------|-------------|
| `live_hosts.csv` | Responding hosts with metadata (status, title, IP, etc.) |
| `dead_hosts.csv` | Non-responding hosts (subdomain takeover candidates) |
| `ip_groups.csv` | Subdomains grouped by IP address |
| `out_of_scope.txt` | Filtered out-of-scope subdomains (for reference) |
| `metadata.json` | Execution statistics |

**live_hosts.csv columns:**

```
subdomain, url, ip, port, status_code, title, content_length, 
web_server, redirect_url, response_time_ms, cname, cdn, scheme
```

---

### Phase 3: Content Discovery 🔄 PLANNED

**Components:**
- **JavaScript Analyzer** - Extract endpoints, secrets, interesting strings from JS files
- **Wayback Finder** - Discover historical endpoints that might still exist
- **Endpoint Aggregator** - Merge and deduplicate all discovered endpoints

---

### Phase 4: Analysis 🔄 PLANNED

**Components (the edge):**
- **Parameter Reflection Mapper** - Find where input reflects and how it's encoded
- **Error Response Analyzer** - Trigger errors to find info leaks, stack traces
- **Auth Flow Mapper** - Map authentication mechanisms and potential weaknesses
- **Pattern Predictor** - Predict undiscovered subdomains from naming patterns

---

### Phase 5: Vulnerability Checks 🔄 PLANNED

**Components:**
- **Subdomain Takeover** - Check dead hosts for claimable services
- **Misconfiguration Checks** - CORS, exposed .git, debug endpoints, etc.

---

## Directory Structure

```
recon-suite/
├── README.md                   # This file
├── scope.json.example          # Scope template
├── config.json.example         # Configuration template
│
├── core/                       # Shared modules
│   ├── scope.py               # Scope validation
│   └── config.py              # Configuration management
│
├── passive-recon/              # Phase 1
│   ├── master_enum.py
│   ├── tools/
│   └── utils/
│
├── resolution/                 # Phase 2
│   ├── resolver_main.py       # Main orchestrator
│   ├── httpx_runner.py        # httpx wrapper
│   └── ip_grouper.py          # IP grouping
│
├── discovery/                  # Phase 3 (planned)
├── analysis/                   # Phase 4 (planned)
├── vulnchecks/                 # Phase 5 (planned)
│
└── projects/                   # Your engagement data
    └── target-corp/
        ├── scope.json
        ├── config.json
        ├── phase1-passive/
        ├── phase2-resolution/
        └── ...
```

---

## Configuration

### scope.json

```json
{
  "name": "Program Name",
  "in_scope": [
    "*.target.com",
    "specific.other.com"
  ],
  "out_of_scope": [
    "support.target.com",
    "*.cdn.target.com"
  ]
}
```

**Pattern support:**
- `*.target.com` - All subdomains of target.com
- `target.com` - Exact match
- `specific.other.com` - Exact match

### config.json

See `config.json.example` for all options. Key settings:

```json
{
  "phase2": {
    "httpx": {
      "threads": 50,
      "timeout": 10,
      "ports": [80, 443, 8080, 8443],
      "rate_limit": 150
    }
  }
}
```

---

## Requirements

**External tools:**
- httpx: https://github.com/projectdiscovery/httpx/releases

**Python packages:**
```bash
pip install -r requirements.txt
```

---

## Workflow Example

```bash
# 1. Setup
mkdir -p projects/acme-corp && cd projects/acme-corp
cp ../../scope.json.example scope.json
# Edit scope.json

# 2. Phase 1: Passive enumeration
echo "acme.com" > input/domains.txt
python ../../passive-recon/master_enum.py

# 3. Review Phase 1 results
cat output/final_results.csv | head -20

# 4. Phase 2: Resolution
python ../../resolution/resolver_main.py \
    -i output/final_results.csv \
    -s scope.json

# 5. Review Phase 2 results
cat phase2-resolution/live_hosts.csv | head -20
cat phase2-resolution/ip_groups.csv

# 6. Identify interesting targets
# - Hosts with 401/403 (something protected)
# - Unique IPs (standalone services)
# - Multiple hosts on same IP (test once)

# 7. Continue to Phase 3...
```

---

## License

MIT
