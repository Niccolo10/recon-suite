"""
crt.sh Certificate Transparency Log tool
Queries crt.sh API for subdomains from SSL certificates
"""

import requests
import json
import time
from typing import List, Tuple, Dict

from .base_tool import BaseTool


class CrtshTool(BaseTool):
    """crt.sh certificate transparency enumeration"""
    
    def __init__(self, config: Dict = None):
        config = config or {}
        super().__init__(config)
        self.name = "crtsh"
        self.base_url = "https://crt.sh/"
        self.timeout = config.get('timeout', 30)
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """Query crt.sh for each domain"""
        all_results = []
        
        for domain in domains:
            print(f"  [{self.name}] Querying {domain}...")
            
            try:
                subdomains = self._query_domain(domain)
                print(f"  [{self.name}] Found {len(subdomains)} for {domain}")
                
                for subdomain in subdomains:
                    metadata = {
                        'source': 'crtsh',
                        'parent_domain': domain,
                        'is_wildcard': subdomain.startswith('*.')
                    }
                    all_results.append((subdomain, metadata))
                
                time.sleep(1)
                
            except Exception as e:
                print(f"  [{self.name}] Error for {domain}: {str(e)}")
                continue
        
        return all_results
    
    def _query_domain(self, domain: str) -> List[str]:
        """Query crt.sh API for a specific domain (robust + properly URL-encoded)."""
        domain_lc = domain.strip().lower()

        # Use params= so requests URL-encodes '%' -> '%25'
        params = {"q": f"%.{domain_lc}", "output": "json"}
        headers = {"User-Agent": "recon-suite/1.0"}

        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )

            if response.status_code != 200:
                # Keep logs readable (crt.sh can return long HTML)
                body_preview = (response.text or "").strip().replace("\n", " ")[:300]
                raise RuntimeError(f"HTTP {response.status_code}: {body_preview}")

            # Parse JSON response
            try:
                certs = response.json()
            except ValueError as e:  # requests raises ValueError on JSON decode errors
                text_preview = (response.text or "").strip().replace("\n", " ")[:300]
                raise RuntimeError(f"Invalid JSON: {e}. Body preview: {text_preview}")

            subdomains: set[str] = set()

            for cert in certs:
                name_value = (cert.get("name_value") or "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if not name:
                        continue

                    # Avoid substring false positives (e.g., "evilcapital.com" contains "capital.com")
                    if name == domain_lc or name.endswith("." + domain_lc) or name.endswith("*." + domain_lc):
                        subdomains.add(name)

            return sorted(subdomains)

        except requests.exceptions.Timeout:
            raise RuntimeError(f"Timeout after {self.timeout}s")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}")

