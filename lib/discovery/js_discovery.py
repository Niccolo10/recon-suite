"""
JavaScript Discovery Module
Finds JavaScript files via HTML crawling and Wayback Machine
"""

import re
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class JSDiscovery:
    """Discovers JavaScript files from live hosts"""

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('timeout', 30)
        self.rate_limit = config.get('rate_limit', 2)
        self.user_agents = config.get('user_agents', [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ])
        self.wayback_config = config.get('wayback', {})
        self.wayback_enabled = self.wayback_config.get('enabled', True)
        self.years_back = self.wayback_config.get('years_back', 2)
        self._ua_index = 0
        self._last_request = 0

    def _get_user_agent(self) -> str:
        """Rotate user agents"""
        ua = self.user_agents[self._ua_index % len(self.user_agents)]
        self._ua_index += 1
        return ua

    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        if self.rate_limit > 0:
            elapsed = time.time() - self._last_request
            wait_time = (1.0 / self.rate_limit) - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
        self._last_request = time.time()

    def discover_all(self, hosts: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Discover JS files from all hosts

        Args:
            hosts: List of host dicts with 'url' and 'subdomain' keys

        Returns:
            Dict mapping host -> list of JS file info dicts
        """
        results = {}

        for host in hosts:
            url = host.get('url', '')
            subdomain = host.get('subdomain', '')

            if not url:
                continue

            js_files = self.discover_from_host(url, subdomain)
            if js_files:
                results[subdomain] = js_files

        return results

    def discover_from_host(self, url: str, subdomain: str) -> List[Dict]:
        """
        Discover JS files from a single host

        Returns list of dicts with keys: url, source, type
        """
        js_files = []
        seen_urls = set()

        # 1. Crawl HTML for script tags
        crawl_results = self._crawl_html(url)
        for js_url, js_type in crawl_results:
            if js_url not in seen_urls:
                seen_urls.add(js_url)
                js_files.append({
                    'url': js_url,
                    'source': 'crawl',
                    'type': js_type,
                    'host': subdomain
                })

        # 2. Wayback Machine
        if self.wayback_enabled:
            wayback_results = self._query_wayback(subdomain)
            for js_url in wayback_results:
                if js_url not in seen_urls:
                    seen_urls.add(js_url)
                    js_files.append({
                        'url': js_url,
                        'source': 'wayback',
                        'type': 'external',
                        'host': subdomain
                    })

        return js_files

    def _crawl_html(self, url: str) -> List[Tuple[str, str]]:
        """
        Crawl HTML page for JavaScript references

        Returns list of (js_url, type) tuples where type is 'external' or 'inline'
        """
        js_refs = []

        try:
            self._rate_limit_wait()

            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }

            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            if response.status_code != 200:
                return js_refs

            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = url

            # Check for <base> tag
            base_tag = soup.find('base', href=True)
            if base_tag:
                base_url = urljoin(url, base_tag['href'])

            # External scripts
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = self._resolve_url(src, base_url)
                if full_url and self._is_js_url(full_url):
                    js_refs.append((full_url, 'external'))

                    # Check for source map
                    map_url = full_url + '.map'
                    js_refs.append((map_url, 'sourcemap'))

            # Inline scripts - check for sourceMappingURL
            for script in soup.find_all('script'):
                if script.string:
                    source_map = self._extract_source_map_url(script.string, base_url)
                    if source_map:
                        js_refs.append((source_map, 'sourcemap'))

            # Also check response headers for additional JS hints
            content = response.text

            # Look for dynamically loaded scripts in HTML
            dynamic_patterns = [
                r'src\s*[=:]\s*["\']([^"\']+\.js[^"\']*)["\']',
                r'import\s+.*?from\s+["\']([^"\']+\.js)["\']',
                r'require\s*\(\s*["\']([^"\']+\.js)["\']',
            ]

            for pattern in dynamic_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    full_url = self._resolve_url(match, base_url)
                    if full_url and self._is_js_url(full_url):
                        if (full_url, 'external') not in js_refs:
                            js_refs.append((full_url, 'external'))

        except requests.RequestException:
            pass
        except Exception:
            pass

        return js_refs

    def _query_wayback(self, domain: str) -> List[str]:
        """
        Query Wayback Machine for historical JS files

        Returns list of unique JS URLs
        """
        js_urls = []
        seen_paths = set()

        try:
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=365 * self.years_back)

            from_date = start_date.strftime('%Y%m%d')
            to_date = end_date.strftime('%Y%m%d')

            # CDX API query
            cdx_url = 'https://web.archive.org/cdx/search/cdx'

            params = {
                'url': f'*.{domain}/*',
                'matchType': 'domain',
                'filter': 'mimetype:application/javascript|mimetype:text/javascript',
                'from': from_date,
                'to': to_date,
                'output': 'json',
                'fl': 'original,timestamp,mimetype',
                'collapse': 'urlkey',
                'limit': '1000'
            }

            self._rate_limit_wait()

            response = requests.get(
                cdx_url,
                params=params,
                timeout=self.wayback_config.get('timeout', 30)
            )

            if response.status_code != 200:
                return js_urls

            data = response.json()

            # Skip header row
            if data and len(data) > 1:
                for row in data[1:]:
                    if len(row) >= 1:
                        original_url = row[0]

                        # Dedupe by path (ignore query strings for dedup)
                        parsed = urlparse(original_url)
                        path_key = f"{parsed.netloc}{parsed.path}"

                        if path_key not in seen_paths:
                            seen_paths.add(path_key)
                            js_urls.append(original_url)

            # Also try .js extension filter
            params2 = {
                'url': f'*.{domain}/*.js',
                'matchType': 'domain',
                'from': from_date,
                'to': to_date,
                'output': 'json',
                'fl': 'original,timestamp',
                'collapse': 'urlkey',
                'limit': '500'
            }

            self._rate_limit_wait()

            response2 = requests.get(
                cdx_url,
                params=params2,
                timeout=self.wayback_config.get('timeout', 30)
            )

            if response2.status_code == 200:
                data2 = response2.json()
                if data2 and len(data2) > 1:
                    for row in data2[1:]:
                        if len(row) >= 1:
                            original_url = row[0]
                            parsed = urlparse(original_url)
                            path_key = f"{parsed.netloc}{parsed.path}"

                            if path_key not in seen_paths:
                                seen_paths.add(path_key)
                                js_urls.append(original_url)

        except requests.RequestException:
            pass
        except Exception:
            pass

        return js_urls

    def _resolve_url(self, url: str, base_url: str) -> str:
        """Resolve relative URL to absolute"""
        if not url:
            return ''

        # Skip data URLs and blob URLs
        if url.startswith(('data:', 'blob:', 'javascript:')):
            return ''

        # Handle protocol-relative URLs
        if url.startswith('//'):
            parsed_base = urlparse(base_url)
            return f"{parsed_base.scheme}:{url}"

        # Already absolute
        if url.startswith(('http://', 'https://')):
            return url

        # Resolve relative
        return urljoin(base_url, url)

    def _is_js_url(self, url: str) -> bool:
        """Check if URL likely points to JavaScript"""
        if not url:
            return False

        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check extension
        if path.endswith('.js'):
            return True

        # Check for common JS bundle patterns
        js_patterns = [
            r'\.js\?',
            r'/js/',
            r'bundle',
            r'chunk',
            r'vendor',
            r'main\.',
            r'app\.',
        ]

        for pattern in js_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True

        return False

    def _extract_source_map_url(self, content: str, base_url: str) -> str:
        """Extract sourceMappingURL from JS content"""
        patterns = [
            r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
            r'/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/',
        ]

        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                map_url = match.group(1)
                return self._resolve_url(map_url, base_url)

        return ''


def discover_js_files(hosts: List[Dict], config: Dict) -> Dict[str, List[Dict]]:
    """
    Convenience function to discover JS files from hosts

    Args:
        hosts: List of host dicts from phase2/live.csv
        config: Discovery configuration

    Returns:
        Dict mapping host -> list of JS file info
    """
    discovery = JSDiscovery(config)
    return discovery.discover_all(hosts)
