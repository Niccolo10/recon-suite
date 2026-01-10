# Recon Suite

**Professional reconnaissance automation toolkit for external penetration testing.**

---

## 🎯 Overview

Recon Suite is a modular reconnaissance framework designed for penetration testers and bug bounty hunters. It automates the tedious parts of external reconnaissance while maintaining reliability and extensibility.

### Current Modules

| Module | Status | Description |
|--------|--------|-------------|
| **Passive Recon** | ✅ **Production** | Multi-tool subdomain enumeration |
| **Active Recon** | 📋 Planned | WHOIS, port scanning, web probing |
| **Analysis** | 📋 Planned | Asset classification, reporting |
| **Integrations** | 📋 Planned | BBot, Nuclei, FFUF |

---

## 📦 Passive Recon Module

Automated passive subdomain enumeration integrating:

- **Microsoft Threat Intelligence** - Large-scale subdomain discovery
- **SecurityTrails** - Historical DNS data
- **crt.sh** - Certificate Transparency logs
- **Sublist3r** - Search engine aggregation

### Key Features

✅ **Production-Grade Reliability**
- Multi-token/cookie support with rotation
- Automatic retry and error handling
- Checkpoint/resume capability
- Rate limit management

✅ **Smart Deduplication**
- Cross-tool result merging
- Source tracking (which tools found what)
- Confidence scoring (HIGH/MEDIUM/LOW)
- Wildcard detection and flagging

✅ **Parallel Execution**
- Runs all tools simultaneously
- Independent failure isolation
- Progress checkpointing after each tool

✅ **Unified Output**
- Single CSV with all results
- Metadata preservation from all sources
- Ready for active enumeration phase

---

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/Niccolo10/recon-suite.git
cd recon-suite/passive-recon
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure
```bash
cp config.json.example config.json
nano config.json  # Edit with your tokens
```

#### Microsoft TI Setup

1. Login to security.microsoft.com (intercept with Burp)
2. Copy the `Authorization: Bearer ...` header
3. Update in config.json:
```json
{
  "tools": {
    "microsoft_ti": {
      "processes_input": [
        {
          "authorization": "Bearer YOUR_TOKEN_HERE",
          "proxy": null
        }
      ]
    }
  }
}
```

#### SecurityTrails Setup

1. Login to securitytrails.com (intercept with Burp)
2. Copy all cookies
3. Get SEC_ID from URL path (e.g., `/_next/data/452071e4/...`)
4. Update in config.json:
```json
{
  "tools": {
    "securitytrails": {
      "sec_id": "452071e4",
      "processes_input": [
        {
          "cookie": "YOUR_COOKIES_HERE",
          "proxy": null
        }
      ]
    }
  }
}
```

### 4. Add Target Domains
```bash
nano input/domains.txt
```

Add your domains (one per line):
```
example.com
test-domain.com
```

### 5. Run
```bash
python master_enum.py
```

---

## 📊 Output Format

### Main Output: `output/final_results.csv`
```csv
subdomain,apex_domain,ip,source_tools,confidence_score,first_discovered,host_provider,mail_provider,tags,additional_info
api.example.com,example.com,,microsoft_ti;securitytrails;crtsh,HIGH,2025-01-10T14:30:00,Amazon.com Inc,Google LLC,prod,{}
test.example.com,example.com,,securitytrails,MEDIUM,2025-01-10T14:32:00,Cloudflare Inc,,,{}
*.example.com,example.com,,crtsh,LOW,2025-01-10T14:35:00,,,,"{\"wildcard\":true}"
```

**Columns:**
- `subdomain` - Discovered subdomain
- `apex_domain` - Parent domain from input
- `ip` - Empty (filled by active recon)
- `source_tools` - Which tools found it (semicolon-separated)
- `confidence_score` - HIGH (3+ tools), MEDIUM (2), LOW (1)
- `first_discovered` - Timestamp
- `host_provider` - From SecurityTrails
- `mail_provider` - From SecurityTrails
- `tags` - From Microsoft TI
- `additional_info` - JSON metadata

### Statistics: `output/metadata.json`
```json
{
  "execution_time": "2025-01-10T15:00:00",
  "input_domains": ["example.com"],
  "tool_statistics": {
    "microsoft_ti": {
      "success": true,
      "subdomains_found": 5000,
      "elapsed_seconds": 45.2
    }
  },
  "total_subdomains_found": 5100
}
```

---

## ⚙️ Advanced Configuration

### Multiple Tokens/Cookies (Recommended)

For better rate limit handling:
```json
{
  "tools": {
    "microsoft_ti": {
      "processes_input": [
        {
          "authorization": "Bearer TOKEN_1",
          "proxy": {"http": "http://proxy1:8080", "https": "http://proxy1:8080"}
        },
        {
          "authorization": "Bearer TOKEN_2",
          "proxy": null
        }
      ]
    }
  }
}
```

### Disable Specific Tools
```json
{
  "tools": {
    "sublist3r": {
      "enabled": false
    }
  }
}
```

### Sequential Execution

For rate-limited scenarios:
```json
{
  "execution": {
    "parallel_tools": false
  }
}
```

---

## 🔄 Resume Capability

If execution is interrupted:

1. Fix the issue (refresh tokens if needed)
2. Re-run: `python master_enum.py`
3. It will automatically resume from the last completed tool

To start fresh:
```bash
rm checkpoints/state.json
python master_enum.py
```

---

## 🐛 Troubleshooting

### Token/Cookie Expired

**Symptoms:**
- `[AUTH] domain: Invalid or expired token`
- `[ERROR] status 403`

**Solution:**
1. Grab fresh tokens from Burp
2. Update `config.json`
3. Re-run (will resume from checkpoint)

### Rate Limits Hit

**Solutions:**
1. Add more tokens/cookies with different IPs
2. Increase `request_interval` in config
3. Use proxy rotation
4. Run tools sequentially (`parallel_tools: false`)

### Import Errors
```bash
pip install -r requirements.txt
```

---

## 📁 Directory Structure
```
passive-recon/
├── master_enum.py           # Main orchestrator
├── config.json              # Configuration (create from .example)
├── requirements.txt         # Dependencies
│
├── tools/                   # Enumeration tools
│   ├── microsoft_ti.py     # Native MS TI implementation
│   ├── securitytrails.py   # Native SecurityTrails implementation
│   ├── crtsh_tool.py       # crt.sh integration
│   └── sublist3r_tool.py   # Sublist3r integration
│
├── utils/                   # Utilities
│   ├── validator.py        # Domain validation
│   ├── deduplicator.py     # Smart deduplication
│   └── merger.py           # Results merger
│
├── input/
│   └── domains.txt         # Your target domains
│
├── output/
│   ├── final_results.csv   # ⭐ Main output
│   ├── metadata.json       # Statistics
│   └── temp/               # Individual tool outputs
│
└── checkpoints/
    └── state.json          # Resume state
```

---

## 🗺️ Roadmap

### Phase 2: Active Recon
- [ ] WHOIS enrichment integration
- [ ] Parallel port scanning
- [ ] HTTP probing and screenshots
- [ ] SSL certificate analysis

### Phase 3: Analysis
- [ ] Asset classification (On-Prem vs Cloud)
- [ ] Automated reporting
- [ ] Risk scoring

### Phase 4: Integrations
- [ ] BBot deep enumeration
- [ ] Nuclei vulnerability scanning
- [ ] FFUF fuzzing automation

---

## 📝 License

MIT License
---
