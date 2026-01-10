"""
crt.sh Certificate Transparency Log tool
Queries crt.sh API for subdomains from SSL certificates
"""

import requests
import json
import time
from pathlib import Path
from typing import List, Tuple, Dict
from .base_tool import BaseTool


class CrtshTool(BaseTool):
    """crt.sh certificate transparency enumeration"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "crtsh"
        self.base_url = "https://crt.sh/"
        self.timeout = config.get('timeout', 30)
        self.output_file = config.get('output_file', './output/temp/crtsh_subdomains.json')
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """
        Query crt.sh for each domain
        
        Args:
            domains: List of domains to enumerate
            
        Returns:
            List of (subdomain, metadata) tuples
        """
        all_results = []
        
        for domain in domains:
            print(f"[{self.name}] Querying {domain}...")
            
            try:
                subdomains = self._query_domain(domain)
                print(f"[{self.name}] Found {len(subdomains)} subdomains for {domain}")
                
                for subdomain in subdomains:
                    metadata = {
                        'source': 'crtsh',
                        'parent_domain': domain,
                        'is_wildcard': subdomain.startswith('*.')
                    }
                    all_results.append((subdomain, metadata))
                
                # Be nice to crt.sh - small delay between requests
                time.sleep(1)
                
            except Exception as e:
                print(f"[{self.name}] Error querying {domain}: {str(e)}")
                continue
        
        # Save raw results
        self._save_results(all_results)
        
        return all_results
    
    def _query_domain(self, domain: str) -> List[str]:
        """
        Query crt.sh API for a specific domain
        
        Args:
            domain: Domain to query
            
        Returns:
            List of unique subdomains
        """
        # Query for wildcard to get all subdomains
        query = f"%.{domain}"
        url = f"{self.base_url}?q={query}&output=json"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                raise RuntimeError(f"HTTP {response.status_code}: {response.text}")
            
            # Parse JSON response
            certs = response.json()
            
            # Extract unique subdomains
            subdomains = set()
            
            for cert in certs:
                # name_value can contain multiple names separated by newlines
                name_value = cert.get('name_value', '')
                
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    
                    # Only include if it contains the target domain
                    if name and domain.lower() in name:
                        subdomains.add(name)
            
            return sorted(list(subdomains))
            
        except requests.exceptions.Timeout:
            raise RuntimeError(f"Request timed out after {self.timeout}s")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON response: {str(e)}")
    
    def _save_results(self, results: List[Tuple[str, Dict]]):
        """Save results to JSON file for debugging"""
        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to serializable format
        output_data = [
            {
                'subdomain': subdomain,
                'metadata': metadata
            }
            for subdomain, metadata in results
        ]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"[{self.name}] Results saved to: {self.output_file}")