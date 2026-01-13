"""
AlienVault Open Threat Exchange (OTX) tool
Queries OTX API URL list for subdomains
"""

import requests
import time
import random
from typing import List, Dict
from urllib.parse import urlparse

from .base_tool import BaseTool


class AlienVaultOTXTool(BaseTool):
    """AlienVault OTX passive enumeration"""

    def __init__(self, config: Dict = None):
        config = config or {}
        super().__init__(config)
        self.name = "alienvault_otx"
        self.base_url = "https://otx.alienvault.com/api/v1/indicators/domain"
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 5)
        self.api_key = config.get('api_key', None)

    def run(self, domains: List[str]) -> List[str]:
        """Query OTX for each domain and return a list of subdomain strings"""
        all_results: List[str] = []

        # Small initial delay to avoid rate limiting when running in parallel
        time.sleep(random.uniform(1, 3))

        for domain in domains:
            if self.should_stop():
                break
            print(f"  [{self.name}] Querying {domain}...")

            try:
                subdomains = self._query_url_list(domain)
                print(f"  [{self.name}] Found {len(subdomains)} subdomains for {domain}")

                all_results.extend(subdomains)
                time.sleep(1)

            except Exception as e:
                print(f"  [{self.name}] Error for {domain}: {str(e)}")
                continue

        return all_results

    def _query_url_list(self, domain: str) -> List[str]:
        """Query OTX URL list endpoint and extract hostnames"""
        domain_lc = domain.strip().lower()
        subdomains = set()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        page = 1
        max_pages = 10

        while page <= max_pages:
            if self.should_stop():
                break
            try:
                url = f"{self.base_url}/{domain_lc}/url_list?limit=100&page={page}"

                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout
                )

                # Handle rate limiting
                if response.status_code == 429:
                    delay = self.retry_delay * (2 ** (page - 1)) + random.uniform(0, 1)
                    print(f"  [{self.name}] Rate limited, waiting {delay:.1f}s...")
                    time.sleep(delay)
                    continue

                if response.status_code != 200:
                    break

                data = response.json()
                url_list = data.get('url_list', [])

                if not url_list:
                    break

                # Extract hostnames from URLs
                for url_entry in url_list:
                    url_str = url_entry.get('url', '')
                    if not url_str:
                        continue

                    try:
                        parsed = urlparse(url_str)
                        hostname = parsed.netloc.lower().strip()

                        # Remove port if present
                        if ':' in hostname:
                            hostname = hostname.split(':')[0]

                        # Filter to only include subdomains of target domain
                        if hostname and (hostname == domain_lc or hostname.endswith('.' + domain_lc)):
                            subdomains.add(hostname)
                    except Exception:
                        continue

                # Check if there are more pages
                has_next = data.get('has_next', False)
                if not has_next:
                    break

                page += 1
                time.sleep(0.5)

            except Exception as e:
                print(f"  [{self.name}] URL list page {page} error: {str(e)}")
                break

        return sorted(subdomains)
