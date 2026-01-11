"""
Resolution Runner
Resolves subdomains to live/dead hosts using httpx.
Includes deduplication and IP grouping.
"""

import subprocess
import json
import csv
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from ..core.scope import ScopeValidator


def run_resolution(project: Dict) -> Dict:
    """Run resolution phase"""
    phase1_dir = project['phases']['phase1']
    phase2_dir = project['phases']['phase2']
    
    input_file = phase1_dir / 'subdomains.csv'
    
    if not input_file.exists():
        return {
            'success': False, 
            'error': f'Run passive first: python recon.py passive {project["name"]}'
        }
    
    # Load subdomains
    subdomains = load_subdomains(input_file)
    print(f"[RESOLVE] Loaded {len(subdomains)} subdomains")
    
    if not subdomains:
        return {'success': False, 'error': 'No subdomains'}
    
    # Scope filter
    scope = ScopeValidator(project['scope'])
    in_scope, out_of_scope = scope.filter_and_report(subdomains)
    
    if not in_scope:
        return {'success': False, 'error': 'No in-scope subdomains'}
    
    # Save out-of-scope
    if out_of_scope:
        save_list(out_of_scope, phase2_dir / 'out_of_scope.txt')
    
    # Run httpx
    tools_config = project['config'].get('tools', {})
    
    print(f"\n[RESOLVE] Running httpx on {len(in_scope)} subdomains...")
    live_hosts, dead_hosts = run_httpx(in_scope, tools_config)
    
    print(f"[RESOLVE] Live: {len(live_hosts)}, Dead: {len(dead_hosts)}")
    
    # Save outputs
    live_file = phase2_dir / 'live.csv'
    dead_file = phase2_dir / 'dead.csv'
    
    save_live_hosts(live_hosts, live_file)
    save_dead_hosts(dead_hosts, dead_file)
    
    # IP grouping
    ip_groups = group_by_ip(live_hosts)
    save_ip_groups(ip_groups, phase2_dir / 'ip_groups.csv')
    
    # Metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'input_count': len(subdomains),
        'in_scope': len(in_scope),
        'out_of_scope': len(out_of_scope),
        'live': len(live_hosts),
        'dead': len(dead_hosts),
        'unique_ips': len(ip_groups)
    }
    
    with open(phase2_dir / 'metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    return {
        'success': True,
        'live_count': len(live_hosts),
        'dead_count': len(dead_hosts),
        'live_file': str(live_file),
        'dead_file': str(dead_file)
    }


def load_subdomains(csv_file: Path) -> List[str]:
    """Load subdomains from phase1 CSV"""
    subdomains = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            subdomain = row.get('subdomain', '').strip()
            if subdomain:
                subdomains.append(subdomain)
    return subdomains


def save_list(items: List[str], output_file: Path):
    """Save list to text file"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for item in items:
            f.write(f"{item}\n")


def run_httpx(subdomains: List[str], config: Dict) -> Tuple[List[Dict], List[Dict]]:
    """Run httpx and parse results with deduplication"""
    httpx_path = config.get('httpx_path', 'httpx')
    threads = config.get('threads', 50)
    timeout = config.get('timeout', 10)
    retries = config.get('retries', 2)
    ports = config.get('ports', [80, 443, 8080, 8443])
    rate_limit = config.get('rate_limit', 150)
    
    # Verify httpx
    try:
        subprocess.run([httpx_path, '-version'], capture_output=True, timeout=10)
    except FileNotFoundError:
        raise RuntimeError(
            f"httpx not found. Install from: https://github.com/projectdiscovery/httpx/releases"
        )
    
    # Temp files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
        input_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
        output_file = f.name
    
    try:
        cmd = [
            httpx_path,
            '-l', input_file,
            '-o', output_file,
            '-json',
            '-threads', str(threads),
            '-timeout', str(timeout),
            '-retries', str(retries),
            '-rate-limit', str(rate_limit),
            '-silent',
            '-no-color',
            '-status-code',
            '-title',
            '-content-length',
            '-web-server',
            '-ip',
            '-cname',
            '-cdn',
            '-response-time',
            '-location',
            '-follow-redirects',
            '-max-redirects', '10'
        ]
        
        if ports:
            cmd.extend(['-ports', ','.join(str(p) for p in ports)])
        
        start = datetime.now()
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        elapsed = (datetime.now() - start).total_seconds()
        
        print(f"[RESOLVE] httpx completed in {elapsed:.1f}s")
        
        return parse_httpx_output(output_file, subdomains)
        
    finally:
        Path(input_file).unlink(missing_ok=True)
        Path(output_file).unlink(missing_ok=True)


def parse_httpx_output(output_file: str, all_subdomains: List[str]) -> Tuple[List[Dict], List[Dict]]:
    """Parse httpx output with deduplication per subdomain"""
    live_map = {}
    seen = set()
    
    output_path = Path(output_file)
    if output_path.exists() and output_path.stat().st_size > 0:
        with open(output_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    host = extract_host_data(data)
                    
                    if host:
                        key = host['subdomain'].lower()
                        seen.add(key)
                        
                        if key not in live_map:
                            host['all_ports'] = str(host['port'])
                            live_map[key] = host
                        else:
                            existing = live_map[key]
                            # Track all ports
                            ports = existing.get('all_ports', '')
                            new_port = str(host['port'])
                            if new_port and new_port not in ports.split(';'):
                                existing['all_ports'] = f"{ports};{new_port}" if ports else new_port
                            
                            # Prefer HTTPS and 200
                            if host['scheme'] == 'https' and existing['scheme'] == 'http':
                                host['all_ports'] = existing['all_ports']
                                live_map[key] = host
                            elif host['status_code'] == 200 and existing['status_code'] != 200:
                                host['all_ports'] = existing['all_ports']
                                live_map[key] = host
                
                except json.JSONDecodeError:
                    continue
    
    live_hosts = list(live_map.values())
    
    # Dead hosts
    dead_hosts = []
    for subdomain in all_subdomains:
        if subdomain.lower() not in seen:
            dead_hosts.append({'subdomain': subdomain, 'reason': 'no_response'})
    
    return live_hosts, dead_hosts


def extract_host_data(data: Dict) -> Optional[Dict]:
    """Extract relevant fields from httpx output"""
    url = data.get('url', '')
    if not url:
        return None
    
    subdomain = data.get('input', '')
    if not subdomain:
        subdomain = url.replace('http://', '').replace('https://', '').split('/')[0]
        if ':' in subdomain:
            subdomain = subdomain.split(':')[0]
    
    return {
        'subdomain': subdomain,
        'url': url,
        'ip': data.get('host', ''),
        'port': data.get('port', ''),
        'status_code': data.get('status_code', ''),
        'title': (data.get('title', '') or '').replace('\n', ' ').replace('\r', '')[:200],
        'content_length': data.get('content_length', ''),
        'web_server': data.get('webserver', ''),
        'redirect_url': data.get('final_url', '') if data.get('final_url') != url else '',
        'response_time_ms': data.get('response_time', ''),
        'cname': ','.join(data.get('cname', [])) if data.get('cname') else '',
        'cdn': data.get('cdn_name', ''),
        'scheme': data.get('scheme', '')
    }


def save_live_hosts(hosts: List[Dict], output_file: Path):
    """Save live hosts to CSV"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    fieldnames = [
        'subdomain', 'url', 'ip', 'port', 'all_ports', 'status_code', 'title',
        'content_length', 'web_server', 'redirect_url', 'response_time_ms',
        'cname', 'cdn', 'scheme'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(hosts)
    
    print(f"[RESOLVE] Saved: {output_file}")


def save_dead_hosts(hosts: List[Dict], output_file: Path):
    """Save dead hosts to CSV"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['subdomain', 'reason'])
        writer.writeheader()
        writer.writerows(hosts)
    
    print(f"[RESOLVE] Saved: {output_file}")


def group_by_ip(hosts: List[Dict]) -> Dict[str, List[str]]:
    """Group subdomains by IP"""
    groups = {}
    seen = {}
    
    for host in hosts:
        ip = host.get('ip', '')
        subdomain = host.get('subdomain', '')
        
        if not ip or not subdomain:
            continue
        
        if ip not in groups:
            groups[ip] = []
            seen[ip] = set()
        
        if subdomain.lower() not in seen[ip]:
            groups[ip].append(subdomain)
            seen[ip].add(subdomain.lower())
    
    return groups


def save_ip_groups(groups: Dict[str, List[str]], output_file: Path):
    """Save IP groups to CSV"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    sorted_groups = sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'subdomain_count', 'subdomains'])
        
        for ip, subdomains in sorted_groups:
            writer.writerow([ip, len(subdomains), ';'.join(subdomains)])
    
    # Summary
    multi = sum(1 for subs in groups.values() if len(subs) > 1)
    if multi > 0:
        print(f"[RESOLVE] Shared infrastructure: {multi} IPs with multiple hosts")
    else:
        print(f"[RESOLVE] No shared infrastructure detected")
    
    print(f"[RESOLVE] Saved: {output_file}")
