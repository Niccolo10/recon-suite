"""
crt.sh Certificate Transparency Log tool
Queries crt.sh API for subdomains from SSL certificates
"""

import requests
import json
import time
import random
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
        self.max_retries = config.get('max_retries', 5)
        self.retry_delay = config.get('retry_delay', 3)  # Base delay in seconds
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """Query crt.sh for each domain"""
        all_results = []

        for domain in domains:
            if self.should_stop():
                break

            print(f"  [{self.name}] Querying {domain}...")

            try:
                subdomains = self._query_domain(domain)
                print(f"  [{self.name}] Found {len(subdomains)} for {domain}")

                for subdomain in subdomains:
                    metadata = {
                        'source': 'crtsh',
                        'parent_domain': domain
                    }
                    all_results.append((subdomain, metadata))

                time.sleep(1)

            except Exception as e:
                print(f"  [{self.name}] Error for {domain}: {str(e)}")
                continue

        return all_results
    
    def _query_domain(self, domain: str) -> List[str]:
        """Query crt.sh API for a specific domain with retry and exponential backoff."""
        domain_lc = domain.strip().lower()

        # Use params= so requests URL-encodes '%' -> '%25'
        params = {"q": f"%.{domain_lc}", "output": "json"}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        last_error = None

        for attempt in range(self.max_retries):
            if self.should_stop():
                return []
            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )

                # Handle 503/502/429 with retry
                if response.status_code in (502, 503, 429, 500):
                    delay = self.retry_delay * (2 ** attempt) + random.uniform(0, 1)
                    if attempt < self.max_retries - 1:
                        print(f"  [{self.name}] {domain}: HTTP {response.status_code}, retry {attempt + 1}/{self.max_retries} in {delay:.1f}s")
                        time.sleep(delay)
                        continue
                    else:
                        raise RuntimeError(f"HTTP {response.status_code} after {self.max_retries} retries")

                if response.status_code != 200:
                    body_preview = (response.text or "").strip().replace("\n", " ")[:200]
                    raise RuntimeError(f"HTTP {response.status_code}: {body_preview}")

                # Parse JSON response
                try:
                    certs = response.json()
                except ValueError as e:
                    text_preview = (response.text or "").strip().replace("\n", " ")[:200]
                    raise RuntimeError(f"Invalid JSON: {e}. Body: {text_preview}")

                subdomains: set[str] = set()

                for cert in certs:
                    name_value = (cert.get("name_value") or "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if not name:
                            continue

                        # Avoid substring false positives and skip wildcard entries
                        if name.startswith('*.'):
                            continue
                        if name == domain_lc or name.endswith("." + domain_lc):
                            subdomains.add(name)

                return sorted(subdomains)

            except requests.exceptions.Timeout:
                last_error = f"Timeout after {self.timeout}s"
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt) + random.uniform(0, 1)
                    print(f"  [{self.name}] {domain}: Timeout, retry {attempt + 1}/{self.max_retries} in {delay:.1f}s")
                    time.sleep(delay)
                    continue
            except requests.exceptions.RequestException as e:
                last_error = f"Request failed: {e}"
                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt) + random.uniform(0, 1)
                    print(f"  [{self.name}] {domain}: {e}, retry {attempt + 1}/{self.max_retries} in {delay:.1f}s")
                    time.sleep(delay)
                    continue

        raise RuntimeError(last_error or "Max retries exceeded")

