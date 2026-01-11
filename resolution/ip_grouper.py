"""
IP Grouper
Groups subdomains by their resolved IP address.
Helps identify when multiple subdomains hit the same server.
"""

import csv
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


class IPGrouper:
    """
    Groups subdomains by resolved IP.
    Useful for:
    - Identifying shared infrastructure (test once, applies to many)
    - Finding anomalies (many subdomains on one IP vs one alone)
    - Prioritizing targets
    """
    
    def __init__(self):
        self.ip_groups = defaultdict(list)
    
    def process(self, live_hosts_file: str, output_file: str) -> str:
        """
        Process live hosts CSV and group by IP.
        
        Args:
            live_hosts_file: Path to live_hosts.csv from httpx
            output_file: Path to save IP groups CSV
            
        Returns:
            Path to output file
        """
        # Clear previous data
        self.ip_groups = defaultdict(list)
        
        # Load and group
        self._load_live_hosts(live_hosts_file)
        
        # Save results
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._save_groups(output_path)
        
        # Print summary
        self._print_summary()
        
        return str(output_path)
    
    def _load_live_hosts(self, csv_file: str):
        """Load live hosts and group by IP, deduplicating by subdomain"""
        # Track seen subdomains per IP to avoid duplicates from multiple ports
        seen_per_ip = defaultdict(set)
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                ip = row.get('ip', '').strip()
                subdomain = row.get('subdomain', '').strip()
                url = row.get('url', '').strip()
                status_code = row.get('status_code', '')
                title = row.get('title', '')
                port = row.get('port', '')
                
                if not ip or not subdomain:
                    continue
                
                # Skip if we've already seen this subdomain for this IP
                if subdomain.lower() in seen_per_ip[ip]:
                    continue
                
                seen_per_ip[ip].add(subdomain.lower())
                
                self.ip_groups[ip].append({
                    'subdomain': subdomain,
                    'url': url,
                    'status_code': status_code,
                    'title': title,
                    'port': port
                })
    
    def _save_groups(self, output_path: Path):
        """Save IP groups to CSV"""
        # Sort by count (most subdomains first)
        sorted_ips = sorted(
            self.ip_groups.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['ip', 'subdomain_count', 'subdomains', 'sample_titles'])
            
            for ip, hosts in sorted_ips:
                subdomains = [h['subdomain'] for h in hosts]
                
                # Get unique titles (sample)
                titles = list(set(h['title'] for h in hosts if h['title']))[:3]
                
                writer.writerow([
                    ip,
                    len(hosts),
                    ';'.join(subdomains),
                    ' | '.join(titles)
                ])
        
        print(f"[IP-GROUP] Saved IP groups: {output_path}")
    
    def _print_summary(self):
        """Print grouping summary"""
        total_ips = len(self.ip_groups)
        total_hosts = sum(len(hosts) for hosts in self.ip_groups.values())
        
        # Find interesting patterns
        single_host_ips = sum(1 for hosts in self.ip_groups.values() if len(hosts) == 1)
        multi_host_ips = total_ips - single_host_ips
        
        print(f"\n[IP-GROUP] Summary:")
        print(f"  Total unique IPs: {total_ips}")
        print(f"  Total hosts mapped: {total_hosts}")
        print(f"  IPs with single host: {single_host_ips}")
        print(f"  IPs with multiple hosts: {multi_host_ips}")
        
        # Only show top IPs if there's actual grouping (multiple hosts per IP)
        if multi_host_ips > 0:
            # Get IPs with multiple hosts
            multi_host_groups = [
                (ip, hosts) for ip, hosts in self.ip_groups.items() 
                if len(hosts) > 1
            ]
            multi_host_groups.sort(key=lambda x: len(x[1]), reverse=True)
            
            print(f"\n[IP-GROUP] Shared infrastructure detected:")
            for ip, hosts in multi_host_groups[:10]:
                subdomains = [h['subdomain'] for h in hosts]
                sample = ', '.join(subdomains[:3])
                if len(hosts) > 3:
                    sample += f"... (+{len(hosts)-3} more)"
                print(f"    {ip}: {len(hosts)} hosts ({sample})")
        else:
            print(f"\n[IP-GROUP] No shared infrastructure detected (each subdomain has unique IP)")
    
    def get_groups(self) -> Dict[str, List[Dict]]:
        """Get IP groups dictionary"""
        return dict(self.ip_groups)
    
    def get_single_host_ips(self) -> List[str]:
        """Get IPs that only have one subdomain - potentially interesting standalone services"""
        return [ip for ip, hosts in self.ip_groups.items() if len(hosts) == 1]
    
    def get_multi_host_ips(self) -> List[str]:
        """Get IPs that have multiple subdomains - shared infrastructure"""
        return [ip for ip, hosts in self.ip_groups.items() if len(hosts) > 1]


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ip_grouper.py <live_hosts.csv> [output.csv]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "ip_groups.csv"
    
    grouper = IPGrouper()
    grouper.process(input_file, output_file)
