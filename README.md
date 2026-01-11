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

**Output:** `phase1/subdomains.csv`

```csv
subdomain,apex_domain,sources,confidence,is_wildcard,host_provider,mail_provider,tags,first_seen
api.target.com,target.com,crtsh;sublist3r,MEDIUM,False,,,2025-01-11T...
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

### Phase 3: Discovery 🔄 (Coming Soon)

- JavaScript endpoint extraction
- Wayback historical URLs

---

### Phase 4: Analysis 🔄 (Coming Soon)

- Parameter reflection mapping
- Error response analysis
- Auth flow mapping
- Naming pattern prediction

---

### Phase 5: Vulnerability Checks 🔄 (Coming Soon)

- Subdomain takeover detection
- Misconfiguration checks

---

## Requirements

**Python packages:**
```bash
pip install -r requirements.txt
```

**External tools:**
- httpx: https://github.com/projectdiscovery/httpx/releases

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
