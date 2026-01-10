"""
httpx Runner
Wraps httpx for subdomain resolution with smart output parsing.
Separates live hosts from dead hosts.
"""

import subprocess
import json
import csv
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from datetime import datetime


class HttpxRunner:
    """
    Wraps httpx for HTTP/HTTPS probing.
    Parses output and separates live/dead hosts.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize httpx runner.
        
        Args:
            config: httpx configuration dict with keys:
                - threads: Number of concurrent threads (default 50)
                - timeout: Request timeout in seconds (default 10)
                - retries: Number of retries (default 2)
                - follow_redirects: Follow redirects (default True)
                - ports: List of ports to check (default [80, 443, 8080, 8443])
                - rate_limit: Requests per second (default 150)
                - httpx_path: Path to httpx binary (default: assumes in PATH)
        """
        self.threads = config.get('threads', 50)
        self.timeout = config.get('timeout', 10)
        self.retries = config.get('retries', 2)
        self.follow_redirects = config.get('follow_redirects', True)
        self.ports = config.get('ports', [80, 443, 8080, 8443])
        self.rate_limit = config.get('rate_limit', 150)
        self.httpx_path = config.get('httpx_path', 'httpx')
        
        # Verify httpx is available
        self._verify_httpx()
    
    def _verify_httpx(self):
        """Verify httpx is installed and accessible"""
        try:
            result = subprocess.run(
                [self.httpx_path, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Extract version from output
                version_line = result.stdout.strip().split('\n')[0] if result.stdout else "unknown"
                print(f"[HTTPX] Found: {version_line}")
            else:
                raise RuntimeError("httpx returned non-zero exit code")
        except FileNotFoundError:
            raise RuntimeError(
                f"httpx not found at '{self.httpx_path}'. "
                "Install it from: https://github.com/projectdiscovery/httpx/releases"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("httpx version check timed out")
    
    def run(self, subdomains: List[str], output_dir: str) -> Tuple[str, str]:
        """
        Run httpx on list of subdomains.
        
        Args:
            subdomains: List of subdomains to probe
            output_dir: Directory to save outputs
            
        Returns:
            Tuple of (live_hosts_file, dead_hosts_file)
        """
        if not subdomains:
            print("[HTTPX] No subdomains to probe")
            return None, None
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[HTTPX] Starting probe of {len(subdomains)} subdomains")
        print(f"[HTTPX] Ports: {self.ports}")
        print(f"[HTTPX] Threads: {self.threads}, Timeout: {self.timeout}s")
        
        # Create temp file with subdomains
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
            input_file = f.name
        
        # Create temp file for httpx JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            httpx_output_file = f.name
        
        try:
            # Build httpx command
            cmd = self._build_command(input_file, httpx_output_file)
            
            print(f"[HTTPX] Running: {' '.join(cmd[:5])}...")  # Show first few args
            
            # Run httpx
            start_time = datetime.now()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour max
            )
            
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"[HTTPX] Completed in {elapsed:.1f}s")
            
            if result.returncode != 0 and not Path(httpx_output_file).exists():
                print(f"[HTTPX] Warning: httpx returned code {result.returncode}")
                if result.stderr:
                    print(f"[HTTPX] stderr: {result.stderr[:500]}")
            
            # Parse results
            live_hosts, dead_hosts = self._parse_results(
                httpx_output_file, 
                subdomains
            )
            
            # Save to CSV files
            live_file = self._save_live_hosts(live_hosts, output_path / 'live_hosts.csv')
            dead_file = self._save_dead_hosts(dead_hosts, output_path / 'dead_hosts.csv')
            
            print(f"\n[HTTPX] Results:")
            print(f"  Live hosts: {len(live_hosts)}")
            print(f"  Dead hosts: {len(dead_hosts)}")
            
            return str(live_file), str(dead_file)
            
        finally:
            # Cleanup temp files
            Path(input_file).unlink(missing_ok=True)
            Path(httpx_output_file).unlink(missing_ok=True)
    
    def _build_command(self, input_file: str, output_file: str) -> List[str]:
        """Build httpx command with all options"""
        cmd = [
            self.httpx_path,
            '-l', input_file,
            '-o', output_file,
            '-json',  # JSON output for parsing
            '-threads', str(self.threads),
            '-timeout', str(self.timeout),
            '-retries', str(self.retries),
            '-rate-limit', str(self.rate_limit),
            '-silent',  # Reduce noise
            '-no-color',
            # Output fields we want
            '-status-code',
            '-title',
            '-content-length',
            '-web-server',
            '-ip',
            '-cname',
            '-cdn',
            '-response-time',
            '-location',  # Redirect location
        ]
        
        # Add ports
        if self.ports:
            cmd.extend(['-ports', ','.join(str(p) for p in self.ports)])
        
        # Follow redirects
        if self.follow_redirects:
            cmd.append('-follow-redirects')
            cmd.extend(['-max-redirects', '10'])
        
        return cmd
    
    def _parse_results(self, httpx_output: str, all_subdomains: List[str]) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse httpx JSON output and separate live/dead hosts.
        Deduplicates multiple port responses per subdomain.
        
        Args:
            httpx_output: Path to httpx JSON output file
            all_subdomains: Original list of all subdomains
            
        Returns:
            Tuple of (live_hosts, dead_hosts) as list of dicts
        """
        # Use dict to deduplicate by subdomain, keeping best response
        live_hosts_map = {}
        seen_subdomains = set()
        
        # Parse httpx output
        output_path = Path(httpx_output)
        if output_path.exists() and output_path.stat().st_size > 0:
            with open(output_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        
                        # Extract relevant fields
                        host_data = self._extract_host_data(data)
                        
                        if host_data:
                            subdomain_key = host_data['subdomain'].lower()
                            seen_subdomains.add(subdomain_key)
                            
                            # Decide whether to keep this response
                            if subdomain_key not in live_hosts_map:
                                # First response for this subdomain
                                host_data['all_ports'] = str(host_data['port'])
                                live_hosts_map[subdomain_key] = host_data
                            else:
                                # Already have a response - merge ports and keep better one
                                existing = live_hosts_map[subdomain_key]
                                
                                # Track all responding ports
                                existing_ports = existing.get('all_ports', '')
                                new_port = str(host_data['port'])
                                if new_port and new_port not in existing_ports.split(';'):
                                    existing['all_ports'] = f"{existing_ports};{new_port}" if existing_ports else new_port
                                
                                # Prefer HTTPS over HTTP
                                if host_data['scheme'] == 'https' and existing['scheme'] == 'http':
                                    host_data['all_ports'] = existing['all_ports']
                                    live_hosts_map[subdomain_key] = host_data
                                # Prefer 200 over other status codes
                                elif host_data['status_code'] == 200 and existing['status_code'] != 200:
                                    host_data['all_ports'] = existing['all_ports']
                                    live_hosts_map[subdomain_key] = host_data
                    
                    except json.JSONDecodeError:
                        continue
        
        # Convert map to list
        live_hosts = list(live_hosts_map.values())
        
        # Identify dead hosts (subdomains that didn't respond on any port)
        dead_hosts = []
        for subdomain in all_subdomains:
            subdomain_lower = subdomain.lower()
            if subdomain_lower not in seen_subdomains:
                dead_hosts.append({
                    'subdomain': subdomain,
                    'reason': 'no_response'
                })
        
        return live_hosts, dead_hosts
    
    def _extract_host_data(self, data: Dict) -> Optional[Dict]:
        """Extract relevant data from httpx JSON output"""
        url = data.get('url', '')
        if not url:
            return None
        
        # Extract subdomain from URL
        # URL format: https://subdomain.domain.com:port
        subdomain = data.get('input', '')
        if not subdomain:
            # Try to extract from URL
            subdomain = url.replace('http://', '').replace('https://', '').split('/')[0]
            if ':' in subdomain:
                subdomain = subdomain.split(':')[0]
        
        return {
            'subdomain': subdomain,
            'url': url,
            'ip': data.get('host', ''),  # Resolved IP
            'port': data.get('port', ''),
            'status_code': data.get('status_code', ''),
            'title': (data.get('title', '') or '').replace('\n', ' ').replace('\r', '')[:200],  # Truncate long titles
            'content_length': data.get('content_length', ''),
            'web_server': data.get('webserver', ''),
            'redirect_url': data.get('final_url', '') if data.get('final_url') != url else '',
            'response_time_ms': data.get('response_time', ''),
            'cname': ','.join(data.get('cname', [])) if data.get('cname') else '',
            'cdn': data.get('cdn_name', ''),
            'scheme': data.get('scheme', '')
        }
    
    def _save_live_hosts(self, hosts: List[Dict], output_file: Path) -> Path:
        """Save live hosts to CSV"""
        if not hosts:
            # Create empty file with headers
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'subdomain', 'url', 'ip', 'port', 'all_ports', 'status_code', 'title',
                    'content_length', 'web_server', 'redirect_url', 'response_time_ms',
                    'cname', 'cdn', 'scheme'
                ])
            return output_file
        
        fieldnames = [
            'subdomain', 'url', 'ip', 'port', 'all_ports', 'status_code', 'title',
            'content_length', 'web_server', 'redirect_url', 'response_time_ms',
            'cname', 'cdn', 'scheme'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(hosts)
        
        print(f"[HTTPX] Live hosts saved: {output_file}")
        return output_file
    
    def _save_dead_hosts(self, hosts: List[Dict], output_file: Path) -> Path:
        """Save dead hosts to CSV"""
        fieldnames = ['subdomain', 'reason']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(hosts)
        
        print(f"[HTTPX] Dead hosts saved: {output_file}")
        return output_file


def load_subdomains_from_csv(csv_file: str, subdomain_column: str = 'subdomain') -> List[str]:
    """
    Load subdomains from Phase 1 CSV output.
    
    Args:
        csv_file: Path to CSV file
        subdomain_column: Name of column containing subdomains
        
    Returns:
        List of subdomains
    """
    subdomains = []
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            subdomain = row.get(subdomain_column, '').strip()
            if subdomain:
                subdomains.append(subdomain)
    
    return subdomains


if __name__ == "__main__":
    # Quick test
    config = {
        'threads': 50,
        'timeout': 10,
        'ports': [80, 443]
    }
    
    runner = HttpxRunner(config)
    print("httpx runner initialized successfully")
