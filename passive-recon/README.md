# Passive Recon Module

Automated passive subdomain enumeration using multiple tools.

## Quick Start
```bash
cd passive-recon
pip install -r requirements.txt
cp config.json.example config.json
# Edit config.json with your auth tokens
python master_enum.py
```

## Features

- Microsoft Threat Intelligence integration
- SecurityTrails integration
- crt.sh Certificate Transparency
- Sublist3r search engine aggregation
- Smart deduplication with confidence scoring
- Checkpoint/resume capability

## Output

Results saved to:
- `output/final_results.csv` - Main deduplicated output
- `output/metadata.json` - Execution statistics
- `output/temp/*` - Individual tool outputs

See main repository README for detailed documentation.