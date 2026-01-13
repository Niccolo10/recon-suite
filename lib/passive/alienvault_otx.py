"""
AlienVault Open Threat Exchange (OTX) tool
Queries OTX API for passive DNS and URL list data
"""

import requests
import time
import random
from typing import List, Tuple, Dict
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
        self.retry_delay = config.get('retry_delay', 5)  # Increased default for rate limiting
        self.api_key = config.get('api_key', None)  # Optional API key for higher rate limits
        self.rate_limited = False  # Track if we hit rate limits

    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """Query OTX for each domain"""
        all_results = []

        # Small initial delay to avoid rate limiting when running in parallel
        time.sleep(random.uniform(1, 3))

        for domain in domains:
            print(f"  [{self.name}] Querying {domain}...")

            try:
                # Query URL list first (most reliable, less rate limited)
                subdomains_urls = self._query_url_list(domain)
                print(f"  [{self.name}]   - URL list: {len(subdomains_urls)} subdomains")

                # Small delay between API calls
                time.sleep(2)

                # Query passive DNS
                subdomains_dns = self._query_passive_dns(domain)
                print(f"  [{self.name}]   - Passive DNS: {len(subdomains_dns)} subdomains")

                # Small delay between API calls
                time.sleep(2)

                # Also query general info endpoint for additional data
                subdomains_general = self._query_general_info(domain)
                print(f"  [{self.name}]   - General info: {len(subdomains_general)} subdomains")

                # Combine and deduplicate
                all_subdomains = set(subdomains_dns + subdomains_urls + subdomains_general)

                print(f"  [{self.name}] Total found: {len(all_subdomains)} unique for {domain}")

                for subdomain in all_subdomains:
                    metadata = {
                        'source': 'alienvault_otx',
                        'parent_domain': domain,
                        'is_wildcard': subdomain.startswith('*.')
                    }
                    all_results.append((subdomain, metadata))

                time.sleep(1)

            except Exception as e:
                print(f"  [{self.name}] Error for {domain}: {str(e)}")
                continue

        return all_results

    def _query_passive_dns(self, domain: str) -> List[str]:
        """Query OTX passive DNS endpoint for subdomains"""
        domain_lc = domain.strip().lower()
        url = f"{self.base_url}/{domain_lc}/passive_dns"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        last_error = None

        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout
                )

                # Handle rate limiting and server errors
                if response.status_code in (429, 500, 502, 503):
                    delay = self.retry_delay * (2 ** attempt) + random.uniform(0, 1)
                    if attempt < self.max_retries - 1:
                        print(f"  [{self.name}] {domain}: HTTP {response.status_code}, retry {attempt + 1}/{self.max_retries} in {delay:.1f}s")
                        time.sleep(delay)
                        continue
                    else:
                        # Return empty on rate limit instead of raising error
                        print(f"  [{self.name}] {domain}: Rate limited (HTTP {response.status_code}), skipping passive_dns")
                        return []

                if response.status_code != 200:
                    body_preview = (response.text or "").strip().replace("\n", " ")[:200]
                    raise RuntimeError(f"HTTP {response.status_code}: {body_preview}")

                # Parse JSON response
                try:
                    data = response.json()
                except ValueError as e:
                    text_preview = (response.text or "").strip().replace("\n", " ")[:200]
                    raise RuntimeError(f"Invalid JSON: {e}. Body: {text_preview}")

                subdomains = set()

                # Extract hostnames from passive DNS records
                passive_dns = data.get('passive_dns', [])
                for record in passive_dns:
                    hostname = record.get('hostname', '').strip().lower()
                    if not hostname:
                        continue

                    # Filter to only include subdomains of target domain
                    if hostname == domain_lc or hostname.endswith('.' + domain_lc):
                        subdomains.add(hostname)

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
        max_pages = 10  # Limit to prevent infinite loops

        while page <= max_pages:
            try:
                url = f"{self.base_url}/{domain_lc}/url_list?limit=100&page={page}"

                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout
                )

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
                time.sleep(0.5)  # Be nice to the API

            except Exception as e:
                print(f"  [{self.name}] URL list page {page} error: {str(e)}")
                break

        return sorted(subdomains)

    def _query_general_info(self, domain: str) -> List[str]:
        """Query OTX general info endpoint for related hostnames"""
        domain_lc = domain.strip().lower()
        subdomains = set()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:
            # Query general info endpoint
            url = f"{self.base_url}/{domain_lc}/general"

            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code != 200:
                return []

            data = response.json()

            # Extract from whois data if available
            whois = data.get('whois', '')
            if isinstance(whois, str):
                # Parse hostnames from whois text
                import re
                hostname_pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+{re.escape(domain_lc)}'
                matches = re.findall(hostname_pattern, whois.lower())
                for match in matches:
                    if match:
                        hostname = match.rstrip('.') + domain_lc
                        if hostname != domain_lc:
                            subdomains.add(hostname)

            # Extract from validation list
            validation = data.get('validation', [])
            for item in validation:
                if isinstance(item, dict):
                    source = item.get('source', '').lower()
                    if source and (source == domain_lc or source.endswith('.' + domain_lc)):
                        subdomains.add(source)

        except Exception as e:
            print(f"  [{self.name}] General info error: {str(e)}")

        return sorted(subdomains)
