"""
Discovery Runner - Phase 3
JavaScript discovery, download, and analysis pipeline
"""

import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .js_discovery import JSDiscovery
from .js_downloader import JSDownloader
from .js_analyzer import JSAnalyzer
from .linkfinder_wrapper import LinkFinderWrapper, FallbackEndpointExtractor, extract_endpoints, load_file_to_host_mapping
from .trufflehog_wrapper import TruffleHogWrapper, scan_for_secrets


def print_status(message: str, prefix: str = '[DISCOVER]'):
    """Print status message"""
    print(f"{prefix} {message}")


def print_progress(current: int, total: int, item: str = 'items'):
    """Print progress indicator"""
    if total == 0:
        return
    percent = (current / total) * 100
    sys.stdout.write(f'\r[DISCOVER] Processing {current}/{total} {item} ({percent:.0f}%)')
    sys.stdout.flush()


def run_discovery(project: Dict) -> Dict:
    """
    Run content discovery phase

    Pipeline:
    1. Load live hosts from phase2
    2. Discover JS files (crawl + wayback)
    3. Download and beautify JS files
    4. Run LinkFinder for endpoints
    5. Run TruffleHog for secrets
    6. Run custom analyzer
    7. Save consolidated results
    """
    print("\n[DISCOVER] Phase 3: JavaScript Analysis")
    print("=" * 50)

    phase2_dir = project['phases']['phase2']
    phase3_dir = project['phases']['phase3']

    # Check for phase2 completion
    live_file = phase2_dir / 'live.csv'
    if not live_file.exists():
        return {
            'success': False,
            'error': f'Run resolution first: python recon.py resolve {project["name"]}'
        }

    # Load live hosts
    hosts = load_live_hosts(live_file)
    if not hosts:
        return {'success': False, 'error': 'No live hosts found in phase2'}

    print_status(f"Loaded {len(hosts)} live hosts from phase2")

    # Get config
    discovery_config = project['config'].get('discovery', {})
    js_config = discovery_config.get('js_analyzer', {})
    wayback_config = discovery_config.get('wayback', {})
    linkfinder_config = discovery_config.get('linkfinder', {'enabled': True})
    trufflehog_config = discovery_config.get('trufflehog', {'enabled': True})

    # Merge wayback config into js_config
    js_config['wayback'] = wayback_config

    # Statistics
    stats = {
        'hosts_processed': len(hosts),
        'js_urls_found': 0,
        'js_files_downloaded': 0,
        'js_files_deduplicated': 0,
        'endpoints_found': 0,
        'secrets_found': 0,
        'dangerous_functions_found': 0,
        'comments_found': 0,
        'source_maps_found': 0
    }

    # Step 1: Discover JS files
    print_status("Step 1: Discovering JavaScript files...")
    discovery = JSDiscovery(js_config)

    all_js_files = {}
    for i, host in enumerate(hosts):
        print_progress(i + 1, len(hosts), 'hosts')
        js_files = discovery.discover_from_host(host['url'], host['subdomain'])
        if js_files:
            all_js_files[host['subdomain']] = js_files

    print()  # Newline after progress

    total_urls = sum(len(files) for files in all_js_files.values())
    stats['js_urls_found'] = total_urls
    print_status(f"Found {total_urls} JS URLs across {len(all_js_files)} hosts")

    if total_urls == 0:
        print_status("No JavaScript files found. Saving empty results.")
        save_empty_results(phase3_dir, stats)
        return {'success': True, **stats}

    # Save JS inventory
    save_js_inventory(all_js_files, phase3_dir / 'js_inventory.csv')

    # Step 2: Download JS files
    print_status("Step 2: Downloading JavaScript files...")
    downloader = JSDownloader(js_config, phase3_dir)

    download_stats = downloader.download_all(all_js_files)
    stats['js_files_downloaded'] = download_stats['downloaded']
    stats['js_files_deduplicated'] = download_stats['deduplicated']
    stats['source_maps_found'] = download_stats['source_maps']

    print_status(f"Downloaded: {download_stats['downloaded']}, Deduplicated: {download_stats['deduplicated']}, Source maps: {download_stats['source_maps']}")

    if download_stats['downloaded'] == 0 and download_stats['deduplicated'] == 0:
        print_status("No JavaScript files successfully downloaded. Saving empty results.")
        save_empty_results(phase3_dir, stats)
        return {'success': True, **stats}

    # Get downloaded files
    js_files = downloader.get_downloaded_files()
    print_status(f"Analyzing {len(js_files)} unique JS files...")

    # Load file to host mapping for context
    inventory_file = phase3_dir / 'js_files' / 'inventory.json'
    file_to_host = load_file_to_host_mapping(inventory_file)

    # Step 3: Extract endpoints with LinkFinder
    print_status("Step 3: Extracting endpoints...")
    endpoints = extract_endpoints(js_files, linkfinder_config, file_to_host)
    stats['endpoints_found'] = len(endpoints)
    print_status(f"Found {len(endpoints)} unique endpoints")

    # Save endpoints
    save_endpoints(endpoints, phase3_dir / 'endpoints.csv')

    # Step 4: Scan for secrets with TruffleHog
    print_status("Step 4: Scanning for secrets with TruffleHog...")
    js_dir = phase3_dir / 'js_files'
    # Only scan actual JS files, not metadata
    trufflehog_secrets = scan_for_secrets_filtered(js_dir, trufflehog_config)
    print_status(f"TruffleHog found {len(trufflehog_secrets)} potential secrets")

    # Step 5: Run custom analyzer
    print_status("Step 5: Running custom analysis...")
    analyzer = JSAnalyzer()
    custom_results = analyzer.analyze_files(js_files)

    custom_secrets = custom_results['secrets']
    dangerous_functions = custom_results['dangerous_functions']
    comments = custom_results['comments']

    print_status(f"Custom analyzer: {len(custom_secrets)} secrets, {len(dangerous_functions)} dangerous functions, {len(comments)} comments")

    # Merge secrets (TruffleHog + custom)
    all_secrets = merge_secrets(trufflehog_secrets, custom_secrets)
    stats['secrets_found'] = len(all_secrets)
    stats['dangerous_functions_found'] = len(dangerous_functions)
    stats['comments_found'] = len(comments)

    # Step 6: Save all results
    print_status("Saving results...")

    # Save secrets
    save_secrets(all_secrets, phase3_dir / 'secrets.json')

    # Save dangerous functions
    save_dangerous_functions(dangerous_functions, phase3_dir / 'dangerous_functions.json')

    # Save comments
    save_comments(comments, phase3_dir / 'comments.json')

    # Save metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        **stats,
        'tools_used': {
            'linkfinder': LinkFinderWrapper(linkfinder_config).is_available(),
            'trufflehog': TruffleHogWrapper(trufflehog_config).is_available(),
            'custom_analyzer': True
        }
    }
    save_metadata(metadata, phase3_dir / 'metadata.json')

    # Summary
    print()
    print("=" * 50)
    print_status("Phase 3 Complete!")
    print_status(f"  JS Files: {stats['js_files_downloaded']} downloaded, {stats['js_files_deduplicated']} deduplicated")
    print_status(f"  Endpoints: {stats['endpoints_found']}")
    print_status(f"  Secrets: {stats['secrets_found']}")
    print_status(f"  Dangerous Functions: {stats['dangerous_functions_found']}")
    print_status(f"  Interesting Comments: {stats['comments_found']}")
    print()
    print_status(f"Results saved to: {phase3_dir}")

    return {'success': True, **stats}


def load_live_hosts(csv_file: Path) -> List[Dict]:
    """Load live hosts from phase2 CSV"""
    hosts = []

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get('url', '')
            subdomain = row.get('subdomain', '')

            if url and subdomain:
                hosts.append({
                    'url': url,
                    'subdomain': subdomain
                })

    return hosts


def save_js_inventory(js_files: Dict[str, List[Dict]], output_file: Path):
    """Save JS URL inventory to CSV"""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['host', 'url', 'source', 'type'])
        writer.writeheader()

        for host, files in js_files.items():
            for file_info in files:
                writer.writerow({
                    'host': host,
                    'url': file_info.get('url', ''),
                    'source': file_info.get('source', ''),
                    'type': file_info.get('type', '')
                })

    print_status(f"Saved: {output_file}")


def save_endpoints(endpoints: List[Dict], output_file: Path):
    """Save endpoints to CSV with host context"""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['endpoint', 'type', 'host', 'source_file', 'tool'])
        writer.writeheader()
        writer.writerows(endpoints)

    print_status(f"Saved: {output_file}")


def save_secrets(secrets: List[Dict], output_file: Path):
    """Save secrets to JSON"""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Sort by context confidence
    context_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    sorted_secrets = sorted(secrets, key=lambda x: context_order.get(x.get('context', 'LOW'), 3))

    output = {
        'total': len(secrets),
        'by_confidence': {
            'HIGH': len([s for s in secrets if s.get('context') == 'HIGH']),
            'MEDIUM': len([s for s in secrets if s.get('context') == 'MEDIUM']),
            'LOW': len([s for s in secrets if s.get('context') == 'LOW'])
        },
        'findings': sorted_secrets
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print_status(f"Saved: {output_file}")


def save_dangerous_functions(findings: List[Dict], output_file: Path):
    """Save dangerous function findings to JSON"""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Sort by severity
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 3))

    output = {
        'total': len(findings),
        'by_severity': {
            'HIGH': len([f for f in findings if f.get('severity') == 'HIGH']),
            'MEDIUM': len([f for f in findings if f.get('severity') == 'MEDIUM']),
            'LOW': len([f for f in findings if f.get('severity') == 'LOW'])
        },
        'findings': sorted_findings
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print_status(f"Saved: {output_file}")


def save_comments(comments: List[Dict], output_file: Path):
    """Save interesting comments to JSON"""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Group by type
    by_type = {}
    for comment in comments:
        ctype = comment.get('type', 'unknown')
        if ctype not in by_type:
            by_type[ctype] = []
        by_type[ctype].append(comment)

    output = {
        'total': len(comments),
        'by_type': {k: len(v) for k, v in by_type.items()},
        'findings': comments
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)

    print_status(f"Saved: {output_file}")


def save_metadata(metadata: Dict, output_file: Path):
    """Save phase metadata to JSON"""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)


def save_empty_results(phase3_dir: Path, stats: Dict):
    """Save empty result files when no JS found"""
    phase3_dir.mkdir(parents=True, exist_ok=True)

    # Empty endpoints
    with open(phase3_dir / 'endpoints.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['endpoint', 'type', 'source_file', 'tool'])
        writer.writeheader()

    # Empty secrets
    with open(phase3_dir / 'secrets.json', 'w', encoding='utf-8') as f:
        json.dump({'total': 0, 'by_confidence': {}, 'findings': []}, f, indent=2)

    # Empty dangerous functions
    with open(phase3_dir / 'dangerous_functions.json', 'w', encoding='utf-8') as f:
        json.dump({'total': 0, 'by_severity': {}, 'findings': []}, f, indent=2)

    # Empty comments
    with open(phase3_dir / 'comments.json', 'w', encoding='utf-8') as f:
        json.dump({'total': 0, 'by_type': {}, 'findings': []}, f, indent=2)

    # Metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        **stats
    }
    with open(phase3_dir / 'metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)


def scan_for_secrets_filtered(js_dir: Path, config: Dict) -> List[Dict]:
    """
    Scan for secrets but filter out findings from metadata files

    This prevents false positives from our own hashes.json and inventory.json
    """
    all_secrets = scan_for_secrets(js_dir, config)

    # Filter out findings from metadata files
    metadata_files = ['hashes.json', 'inventory.json']
    filtered = []

    for secret in all_secrets:
        file_name = secret.get('file', '')
        # Skip if from metadata file
        if any(mf in file_name for mf in metadata_files):
            continue
        filtered.append(secret)

    return filtered


def merge_secrets(trufflehog_secrets: List[Dict], custom_secrets: List[Dict]) -> List[Dict]:
    """Merge and deduplicate secrets from different tools"""
    all_secrets = []
    seen = set()

    # Add TruffleHog secrets first (higher confidence)
    for secret in trufflehog_secrets:
        key = (secret.get('type', ''), secret.get('value', '')[:30])
        if key not in seen:
            seen.add(key)
            all_secrets.append(secret)

    # Add custom secrets
    for secret in custom_secrets:
        key = (secret.get('type', ''), secret.get('value', '')[:30])
        if key not in seen:
            seen.add(key)
            all_secrets.append(secret)

    return all_secrets
