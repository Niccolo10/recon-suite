"""
Domain Importer
Import domains/URLs directly, skipping passive enumeration
"""

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse


def import_domains(project: Dict, input_file: Path, skip_resolution: bool = False) -> Dict:
    """
    Import domains from a file directly into the project

    This allows running phase 2+ without passive enumeration (phase 1).
    Useful when:
    - You already have a list of subdomains
    - Scope is a single domain without wildcard
    - Testing specific targets

    Args:
        project: Project dict from ProjectManager
        input_file: Path to file with domains/URLs (one per line)
        skip_resolution: If True, treat input as already-resolved URLs

    Returns:
        Dict with import status
    """
    if not input_file.exists():
        return {'success': False, 'error': f'File not found: {input_file}'}

    # Read input file
    entries = read_input_file(input_file)
    if not entries:
        return {'success': False, 'error': 'No valid entries found in file'}

    print(f"[IMPORT] Loaded {len(entries)} entries from {input_file.name}")

    # Categorize entries
    urls, domains = categorize_entries(entries)
    print(f"[IMPORT] URLs: {len(urls)}, Domains: {len(domains)}")

    phase1_dir = project['phases']['phase1']
    phase2_dir = project['phases']['phase2']

    if skip_resolution and urls:
        # Direct URL import - skip to phase 2
        print(f"[IMPORT] Skipping resolution, importing {len(urls)} URLs directly")
        result = create_live_csv_from_urls(urls, phase2_dir)

        # Also create minimal phase1 for consistency
        create_minimal_phase1(urls, phase1_dir)

        return {
            'success': True,
            'mode': 'direct',
            'urls_imported': len(urls),
            'live_file': str(phase2_dir / 'live.csv'),
            'skip_to': 'discover'
        }
    else:
        # Domain import - create phase1 structure for resolution
        all_domains = list(set(domains + extract_domains_from_urls(urls)))

        if not all_domains:
            return {'success': False, 'error': 'No domains found to import'}

        print(f"[IMPORT] Creating phase1 with {len(all_domains)} domains")
        create_phase1_from_domains(all_domains, phase1_dir)

        return {
            'success': True,
            'mode': 'resolve',
            'domains_imported': len(all_domains),
            'subdomains_file': str(phase1_dir / 'subdomains.csv'),
            'skip_to': 'resolve'
        }


def read_input_file(input_file: Path) -> List[str]:
    """Read entries from input file, one per line"""
    entries = []

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    entries.append(line)
    except Exception as e:
        print(f"[IMPORT] Error reading file: {e}")

    return entries


def categorize_entries(entries: List[str]) -> Tuple[List[str], List[str]]:
    """Categorize entries as URLs or domains"""
    urls = []
    domains = []

    for entry in entries:
        if entry.startswith(('http://', 'https://')):
            urls.append(entry)
        elif is_valid_domain(entry):
            domains.append(entry)
        else:
            # Try to parse as domain anyway
            cleaned = entry.lower().strip()
            if is_valid_domain(cleaned):
                domains.append(cleaned)

    return urls, domains


def is_valid_domain(entry: str) -> bool:
    """Check if entry looks like a valid domain"""
    # Basic domain pattern
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, entry))


def extract_domains_from_urls(urls: List[str]) -> List[str]:
    """Extract domain names from URLs"""
    domains = []

    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                # Remove port if present
                domain = parsed.netloc.split(':')[0]
                if domain and is_valid_domain(domain):
                    domains.append(domain)
        except:
            continue

    return list(set(domains))


def create_phase1_from_domains(domains: List[str], phase1_dir: Path) -> None:
    """Create phase1 CSV from domain list"""
    phase1_dir.mkdir(parents=True, exist_ok=True)

    # Create subdomains.csv
    csv_file = phase1_dir / 'subdomains.csv'

    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['subdomain', 'apex_domain', 'sources', 'confidence', 'is_wildcard',
                      'host_provider', 'mail_provider', 'tags', 'first_seen']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for domain in domains:
            # Determine apex domain
            parts = domain.split('.')
            if len(parts) >= 2:
                apex = '.'.join(parts[-2:])
            else:
                apex = domain

            writer.writerow({
                'subdomain': domain,
                'apex_domain': apex,
                'sources': 'import',
                'confidence': 'HIGH',
                'is_wildcard': 'False',
                'host_provider': '',
                'mail_provider': '',
                'tags': 'imported',
                'first_seen': datetime.now().isoformat()
            })

    # Create metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'source': 'import',
        'total_subdomains': len(domains),
        'tools_used': ['import']
    }

    with open(phase1_dir / 'metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    print(f"[IMPORT] Created: {csv_file}")


def create_live_csv_from_urls(urls: List[str], phase2_dir: Path) -> Dict:
    """Create live.csv directly from URLs (skip resolution)"""
    phase2_dir.mkdir(parents=True, exist_ok=True)

    live_file = phase2_dir / 'live.csv'

    with open(live_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['subdomain', 'url', 'ip', 'port', 'all_ports', 'status_code', 'title',
                      'content_length', 'web_server', 'redirect_url', 'response_time_ms',
                      'cname', 'cdn', 'scheme']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0] if parsed.netloc else ''
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            writer.writerow({
                'subdomain': domain,
                'url': url,
                'ip': '',
                'port': port,
                'all_ports': str(port),
                'status_code': '',
                'title': '',
                'content_length': '',
                'web_server': '',
                'redirect_url': '',
                'response_time_ms': '',
                'cname': '',
                'cdn': '',
                'scheme': parsed.scheme
            })

    # Create empty dead.csv
    dead_file = phase2_dir / 'dead.csv'
    with open(dead_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['subdomain', 'reason'])
        writer.writeheader()

    # Create metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'source': 'import',
        'live': len(urls),
        'dead': 0,
        'note': 'Imported directly, not resolved'
    }

    with open(phase2_dir / 'metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)

    print(f"[IMPORT] Created: {live_file}")

    return {'live_count': len(urls)}


def create_minimal_phase1(urls: List[str], phase1_dir: Path) -> None:
    """Create minimal phase1 for consistency when importing URLs directly"""
    domains = extract_domains_from_urls(urls)
    if domains:
        create_phase1_from_domains(domains, phase1_dir)
