"""
Google Dork Tool
Uses Google Programmable Search Engine API to find sensitive files and endpoints.
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Tuple, Optional
from datetime import datetime

from .base_tool import BaseTool


class GoogleDorkTool(BaseTool):
    """
    Google Dorking using Programmable Search Engine API.

    Searches for sensitive files and interesting endpoints using
    targeted dork queries like site:target.com ext:log
    """

    def __init__(self, config: Dict):
        self.api_keys = config.get('api_keys', [])
        self.cx = config.get('cx', '')
        self.dorks = config.get('dorks', [
            'ext:log',
            'ext:env',
            'ext:sql',
            'ext:bak',
            'ext:conf',
            'ext:config',
            'inurl:admin',
            'inurl:api',
            'intitle:index.of'
        ])
        self.results_per_query = config.get('results_per_query', 10)
        self.request_interval = config.get('request_interval', 2)
        self.timeout = config.get('timeout', 30)

        if not self.api_keys:
            raise ValueError("No API keys configured")
        if not self.cx:
            raise ValueError("No Custom Search Engine ID (cx) configured")

        self.current_key_index = 0
        self.key_usage = {key: 0 for key in self.api_keys}

    def _get_next_api_key(self) -> str:
        """Rotate through API keys to distribute quota usage"""
        key = self.api_keys[self.current_key_index]
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        return key

    def _search(self, query: str) -> Optional[Dict]:
        """Execute a single search query"""
        api_key = self._get_next_api_key()

        params = {
            'key': api_key,
            'cx': self.cx,
            'q': query,
            'num': min(self.results_per_query, 10)  # API max is 10 per request
        }

        url = f"https://www.googleapis.com/customsearch/v1?{urllib.parse.urlencode(params)}"

        try:
            request = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode('utf-8'))
                self.key_usage[api_key] = self.key_usage.get(api_key, 0) + 1
                return data

        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"    [!] Rate limited on key ...{api_key[-8:]}, rotating")
                return None
            elif e.code == 403:
                print(f"    [!] Quota exceeded on key ...{api_key[-8:]}")
                return None
            else:
                print(f"    [!] HTTP error {e.code}: {str(e)}")
                return None
        except urllib.error.URLError as e:
            print(f"    [!] URL error: {str(e)}")
            return None
        except Exception as e:
            print(f"    [!] Error: {str(e)}")
            return None

    def _extract_findings(self, search_result: Dict, domain: str, dork: str) -> List[Tuple[str, Dict]]:
        """Extract findings from search results"""
        findings = []

        items = search_result.get('items', [])

        for item in items:
            url = item.get('link', '')
            title = item.get('title', '')
            snippet = item.get('snippet', '')

            # Extract the hostname from the URL
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.netloc
                if ':' in hostname:
                    hostname = hostname.split(':')[0]
            except:
                hostname = domain

            # Create a subdomain entry for the passive runner
            # The URL itself is stored in metadata for later analysis
            metadata = {
                'dork': dork,
                'url': url,
                'title': title,
                'snippet': snippet[:200] if snippet else '',
                'source': 'google_dork',
                'found_at': datetime.now().isoformat()
            }

            findings.append((hostname, metadata))

        return findings

    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """
        Run Google dork searches for all domains.

        Args:
            domains: List of target domains

        Returns:
            List of (subdomain, metadata) tuples containing findings
        """
        all_findings = []
        total_queries = len(domains) * len(self.dorks)
        query_count = 0

        print(f"    [*] Running {len(self.dorks)} dorks on {len(domains)} domain(s)")
        print(f"    [*] Using {len(self.api_keys)} API key(s)")

        for domain in domains:
            print(f"    [*] Dorking: {domain}")
            domain_findings = []

            for dork in self.dorks:
                query_count += 1

                # Build the full query
                query = f"site:{domain} {dork}"

                print(f"        [{query_count}/{total_queries}] {dork}", end='', flush=True)

                result = self._search(query)

                if result:
                    total_results = result.get('searchInformation', {}).get('totalResults', '0')
                    items = result.get('items', [])

                    if items:
                        findings = self._extract_findings(result, domain, dork)
                        domain_findings.extend(findings)
                        print(f" -> {len(items)} results (total: {total_results})")
                    else:
                        print(f" -> 0 results")
                else:
                    print(f" -> error")

                # Rate limiting between requests
                time.sleep(self.request_interval)

            if domain_findings:
                print(f"    [*] {domain}: Found {len(domain_findings)} interesting results")
                all_findings.extend(domain_findings)

        # Print API key usage summary
        print(f"    [*] API key usage: {dict(self.key_usage)}")

        return all_findings

    def run_standalone(self, domains: List[str], output_file: str = None) -> Dict:
        """
        Run as standalone module with detailed output.

        Args:
            domains: List of target domains
            output_file: Optional path to save detailed JSON results

        Returns:
            Result dict with findings organized by domain and dork
        """
        print(f"\n[GOOGLE DORK] Starting dork search for {len(domains)} domain(s)")
        print(f"[GOOGLE DORK] Dorks: {', '.join(self.dorks)}")

        detailed_results = {
            'timestamp': datetime.now().isoformat(),
            'domains': domains,
            'dorks': self.dorks,
            'findings': {}
        }

        findings = self.run(domains)

        # Organize findings by domain and dork
        for hostname, metadata in findings:
            domain_key = hostname
            dork_key = metadata.get('dork', 'unknown')

            if domain_key not in detailed_results['findings']:
                detailed_results['findings'][domain_key] = {}

            if dork_key not in detailed_results['findings'][domain_key]:
                detailed_results['findings'][domain_key][dork_key] = []

            detailed_results['findings'][domain_key][dork_key].append({
                'url': metadata.get('url', ''),
                'title': metadata.get('title', ''),
                'snippet': metadata.get('snippet', '')
            })

        detailed_results['total_findings'] = len(findings)
        detailed_results['unique_hosts'] = len(set(h for h, _ in findings))

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(detailed_results, f, indent=2)
            print(f"[GOOGLE DORK] Saved: {output_file}")

        return {
            'success': True,
            'total': len(findings),
            'unique_hosts': detailed_results['unique_hosts'],
            'details': detailed_results
        }


def run(project: Dict) -> Dict:
    """
    Standalone runner for the Google dork module.
    Called via: python recon.py run <project> google_dork
    """
    config = project['config'].get('passive', {}).get('google_dork', {})
    domains = project['domains']
    output_dir = project['phases']['phase1']

    if not config.get('api_keys') or not config.get('cx'):
        return {
            'success': False,
            'error': 'Google Dork not configured. Add api_keys and cx to config.json'
        }

    try:
        tool = GoogleDorkTool(config)
        output_file = output_dir / 'google_dork_findings.json'
        return tool.run_standalone(domains, str(output_file))
    except Exception as e:
        return {'success': False, 'error': str(e)}
