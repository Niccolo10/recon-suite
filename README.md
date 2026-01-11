# Recon Suite

**Phased reconnaissance framework for bug bounty hunting.**

```
╦═╗┌─┐┌─┐┌─┐┌┐┌  ╔═╗┬ ┬┬┌┬┐┌─┐
╠╦╝├┤ │  │ ││││  ╚═╗│ ││ │ ├┤ 
╩╚═└─┘└─┘└─┘┘└┘  ╚═╝└─┘┴ ┴ └─┘
```

---

## Quick Start

```bash
# 1. Create project
python recon.py new target

# 2. Edit scope and domains
notepad projects/target/scope.json
notepad projects/target/domains.txt

# 3. Run
python recon.py passive target
python recon.py resolve target

# 4. Check status
python recon.py status target
```

---

## Commands

| Command | Description |
|---------|-------------|
| `python recon.py new <project>` | Create new project |
| `python recon.py passive <project>` | Phase 1: Passive subdomain enumeration |
| `python recon.py resolve <project>` | Phase 2: Resolve to live/dead hosts |
| `python recon.py discover <project>` | Phase 3: Content discovery |
| `python recon.py analyze <project>` | Phase 4: Analysis modules |
| `python recon.py vulns <project>` | Phase 5: Vulnerability checks |
| `python recon.py full <project>` | Run all phases |
| `python recon.py status <project>` | Show project status |
| `python recon.py run <project> <module>` | Run specific module |
| `python recon.py list` | List all projects |
| `python recon.py modules` | List available standalone modules |
| `python recon.py import <project> <file>` | Import domains/URLs (skip passive) |
| `python recon.py screenshots <project>` | Run/check gowitness screenshots |

---

## Project Structure

```
recon-suite/
├── recon.py                # Main entry point
├── config.json             # Global tool settings
├── config.json.example     # Full config with all options
│
├── projects/               # Your engagements
│   ├── example/            # Example project (reference)
│   │   ├── scope.json      # Scope definition
│   │   ├── domains.txt     # Target domains
│   │   ├── phase1/         # Passive enumeration output
│   │   ├── phase2/         # Resolution output
│   │   ├── phase3/         # Discovery output
│   │   ├── phase4/         # Analysis output
│   │   └── phase5/         # Vuln check output
│   └── your-target/        # Your projects go here
│
├── lib/                    # Tool code (don't edit)
│   ├── core/               # Project, config, scope
│   ├── passive/            # Enumeration tools
│   ├── resolution/         # httpx wrapper
│   ├── discovery/          # JS analyzer, Wayback
│   ├── analysis/           # Reflection, errors, auth
│   └── vulns/              # Takeover, misconfig
│
└── templates/              # Templates for new projects
```

---

## Configuration

### scope.json (per project)

```json
{
  "name": "Target Bug Bounty",
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

### domains.txt (per project)

```
target.com
target.io
```

### config.json (global)

Default config enables crt.sh and Sublist3r only.

To enable Microsoft TI and SecurityTrails, copy `config.json.example` to `config.json` and fill in your tokens:

```json
{
  "passive": {
    "microsoft_ti": {
      "enabled": true,
      "processes_input": [
        {
          "authorization": "Bearer YOUR_TOKEN",
          "proxy": null
        }
      ]
    },
    "securitytrails": {
      "enabled": true,
      "sec_id": "YOUR_SEC_ID",
      "processes_input": [
        {
          "cookie": "YOUR_COOKIES",
          "proxy": null
        }
      ]
    }
  }
}
```

**Getting tokens:**
- **Microsoft TI**: Login to security.microsoft.com, intercept with Burp, copy `Authorization` header
- **SecurityTrails**: Login to securitytrails.com, copy cookies and sec_id from URL

---

## Phase Details

### Phase 1: Passive Enumeration ✅

**Tools:**
- crt.sh (Certificate Transparency)
- Sublist3r (Search engines)
- Microsoft Threat Intelligence (optional)
- SecurityTrails (optional)
- Google Dork (optional) - runs on main domains only, finds sensitive files/endpoints

**Output:** `phase1/subdomains.csv`, `phase1/google_dork_findings.json`

```csv
subdomain,apex_domain,sources,confidence,is_wildcard,host_provider,mail_provider,tags,first_seen
api.target.com,target.com,crtsh;sublist3r,MEDIUM,False,,,2025-01-11T...
```

**Google Dork config:**
```json
{
  "passive": {
    "google_dork": {
      "enabled": true,
      "api_keys": ["YOUR_GOOGLE_API_KEY"],
      "cx": "YOUR_CUSTOM_SEARCH_ENGINE_ID",
      "dorks": ["ext:log", "ext:env", "ext:sql", "inurl:admin", "inurl:api"]
    }
  }
}
```

---

### Phase 2: Resolution ✅

**Tools:**
- httpx (HTTP probing)

**Features:**
- Multi-port scanning (80, 443, 8080, 8443)
- Scope filtering
- Deduplication per subdomain
- IP grouping

**Output:**
- `phase2/live.csv` - Responding hosts
- `phase2/dead.csv` - Non-responding (takeover candidates)
- `phase2/ip_groups.csv` - Shared infrastructure

---

### Phase 3: JavaScript Analysis ✅

**Tools:**
- HTML Crawler (extracts `<script>` tags)
- Wayback Machine API (historical JS files)
- LinkFinder (endpoint extraction)
- TruffleHog (secret detection)
- Custom analyzer (context-aware secrets, dangerous functions, comments)

**Features:**
- JS file discovery via crawling + Wayback (2 years)
- Automatic deduplication by content hash
- JS beautification for readable analysis
- Source map detection and download
- Context-aware secret detection (HIGH/MEDIUM/LOW confidence)
- Dangerous function patterns (low false-positive)
- Interesting comment mining (TODO, FIXME, passwords)

**Output:**
- `phase3/js_files/` - Downloaded JS files (beautified)
- `phase3/endpoints.csv` - API endpoints for fuzzing
- `phase3/secrets.json` - Detected secrets with confidence levels
- `phase3/dangerous_functions.json` - XSS sinks and injection points
- `phase3/comments.json` - Interesting developer comments
- `phase3/js_inventory.csv` - All discovered JS URLs

**Config:**
```json
{
  "discovery": {
    "js_analyzer": {
      "enabled": true,
      "timeout": 30,
      "max_file_size_mb": 10,
      "rate_limit": 2
    },
    "wayback": {
      "enabled": true,
      "years_back": 2
    },
    "linkfinder": {
      "enabled": true
    },
    "trufflehog": {
      "enabled": true
    }
  }
}
```

---

### Phase 4: Analysis 🔄 (Coming Soon)

- Parameter reflection mapping
- Error response analysis
- Auth flow mapping
- Naming pattern prediction

---

### Phase 5: Vulnerability Checks ✅

**Subdomain Takeover Detection:**
- **nuclei** (primary) - 74+ takeover templates for services like AWS, Azure, Heroku, GitHub Pages, etc.
- **subzy** (fallback) - fingerprint-based detection from can-i-take-over-xyz

**Candidates:**
- Dead hosts from phase2 (prime targets)
- Live hosts with CNAME records (dangling DNS)

**Output:**
- `phase5/takeovers.csv` - Vulnerable subdomains
- `phase5/nuclei_takeover.json` - Raw nuclei output
- `phase5/takeover_metadata.json` - Scan statistics

**Config:**
```json
{
  "vulns": {
    "takeover": {
      "nuclei_path": "nuclei",
      "subzy_path": "subzy",
      "threads": 25,
      "timeout": 10,
      "use_nuclei": true,
      "use_subzy": true
    }
  }
}
```

**Coming Soon:**
- Misconfiguration checks (CORS, exposed .git/.env, security headers)

---

## Direct Domain Import

Skip passive enumeration when you already have a target list:

```bash
# Import domains for resolution
python recon.py import myproject domains.txt
python recon.py resolve myproject

# Import URLs directly (skip resolution too)
python recon.py import myproject urls.txt --direct
python recon.py discover myproject
```

**Input file format:**
```
# domains.txt (one per line)
api.target.com
admin.target.com
app.target.com

# urls.txt (one per line)
https://api.target.com
https://admin.target.com:8443
https://app.target.com/admin
```

---

## Screenshots (Gowitness)

Gowitness runs automatically in background after resolution. Manual control:

```bash
# Check status
python recon.py screenshots myproject --status

# Run manually (background)
python recon.py screenshots myproject

# Run in foreground (blocking)
python recon.py screenshots myproject --foreground
```

**Output:** `phase2/screenshots/`
- `gowitness.csv` - Screenshot results
- `gowitness.sqlite3` - Database
- `*.png` - Screenshot images

**Config:**
```json
{
  "tools": {
    "gowitness_enabled": true,
    "gowitness_threads": 10,
    "gowitness_timeout": 10
  }
}
```

---

## Requirements

**Python packages:**
```bash
pip install -r requirements.txt
```

**External tools:**
- httpx: https://github.com/projectdiscovery/httpx/releases
- nuclei: https://github.com/projectdiscovery/nuclei/releases (for takeover detection)
- subzy: `go install github.com/PentestPad/subzy@latest` (optional, fallback takeover detection)
- LinkFinder: `pip install linkfinder` or https://github.com/GerbenJavado/LinkFinder (for JS endpoint extraction)
- TruffleHog: https://github.com/trufflesecurity/trufflehog/releases (for secret detection)
- Gowitness: https://github.com/sensepost/gowitness/releases (for screenshots)

---

## Example Workflow

```bash
# Create project for Capital.com
python recon.py new capital

# Configure scope
echo '{"name":"Capital","in_scope":["*.capital.com"],"out_of_scope":[]}' > projects/capital/scope.json

# Add domains
echo "capital.com" > projects/capital/domains.txt

# Run passive enumeration
python recon.py passive capital

# Resolve to live hosts
python recon.py resolve capital

# Check results
cat projects/capital/phase2/live.csv
```

---

## License

MIT
