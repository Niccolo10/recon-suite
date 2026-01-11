"""
Google Dork Tool
Uses Google Programmable Search Engine API to find sensitive files and endpoints.

Enhanced with high-value, specific dork queries organized by vulnerability category.
These are NOT the generic dorks everyone uses - these target specific misconfigurations.
"""

import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime

from .base_tool import BaseTool


# High-value dork categories with specific queries that lead to real vulnerabilities
# Each dork is specific and targets a known misconfiguration pattern
DORK_CATEGORIES = {
    "secrets_exposure": {
        "severity": "critical",
        "description": "Exposed secrets, credentials, and API keys",
        "dorks": [
            # Git configuration exposure - reveals repo info, sometimes credentials
            'inurl:".git/config" ext:config',
            # Environment files with production secrets
            'ext:env "DB_PASSWORD" OR "API_KEY" OR "SECRET_KEY"',
            # AWS credentials accidentally committed
            'ext:json "aws_access_key_id" OR "aws_secret_access_key"',
            # Docker environment files
            'inurl:".dockerenv" OR inurl:"docker-compose" ext:yml "password"',
            # Firebase configuration with API keys
            'ext:json "apiKey" "authDomain" "storageBucket"',
        ]
    },
    "source_code_exposure": {
        "severity": "critical",
        "description": "Exposed source code repositories and backups",
        "dorks": [
            # SVN metadata exposure
            'inurl:".svn/entries" OR inurl:".svn/wc.db"',
            # Exposed Mercurial repos
            'inurl:".hg/hgrc"',
            # Backup PHP files with source code
            'ext:phps OR ext:php.bak OR ext:php.old OR ext:php.save',
            # Exposed package files revealing dependencies
            'inurl:"package-lock.json" OR inurl:"composer.lock"',
            # IDE project files with sensitive paths
            'ext:iml "sourceFolder" OR inurl:".idea/workspace.xml"',
        ]
    },
    "debug_endpoints": {
        "severity": "high",
        "description": "Debug interfaces and development endpoints left in production",
        "dorks": [
            # Spring Boot Actuator endpoints - often expose heap dumps, env vars
            'inurl:"/actuator/env" OR inurl:"/actuator/heapdump" OR inurl:"/actuator/mappings"',
            # Laravel Telescope debug dashboard
            'inurl:"/telescope/requests" OR inurl:"/_debugbar"',
            # PHP info pages revealing server configuration
            'intitle:"phpinfo()" "PHP Version" "System"',
            # Django debug mode with settings exposure
            'intitle:"DisallowedHost" "DEBUG = True"',
            # Symfony profiler with request details
            'inurl:"/_profiler" OR inurl:"/_wdt"',
        ]
    },
    "admin_interfaces": {
        "severity": "high",
        "description": "Exposed admin panels and management interfaces",
        "dorks": [
            # Kubernetes Dashboard without auth
            'intitle:"Kubernetes Dashboard" inurl:"/api/v1/namespaces"',
            # Jenkins without auth or with easy bypass
            'intitle:"Dashboard [Jenkins]" inurl:"/script" OR inurl:"/configure"',
            # Exposed database admin tools
            'intitle:"Adminer" "Login" "Server" "Username"',
            # Grafana with default or no auth
            'intitle:"Grafana" inurl:"/d/" OR inurl:"/dashboard"',
            # Kibana exposure
            'intitle:"Kibana" inurl:"/app/kibana" OR inurl:"/app/discover"',
        ]
    },
    "api_documentation": {
        "severity": "medium",
        "description": "Exposed API documentation revealing endpoints and parameters",
        "dorks": [
            # Swagger/OpenAPI documentation
            'inurl:"/swagger-ui.html" OR inurl:"/swagger/index.html" OR inurl:"/api-docs"',
            # GraphQL Playground/GraphiQL exposure
            'inurl:"/graphql" "GraphQL Playground" OR "GraphiQL"',
            # Postman collections with API details
            'ext:json "postman_collection" "request" "header"',
            # API Blueprint documentation
            'inurl:"/docs/api" OR inurl:"/api/documentation" intitle:"API"',
            # gRPC reflection enabled
            'inurl:"/grpc.reflection.v1alpha.ServerReflection"',
        ]
    },
    "sensitive_files": {
        "severity": "medium",
        "description": "Sensitive configuration and data files",
        "dorks": [
            # WordPress configuration backups
            'inurl:"wp-config.php.bak" OR inurl:"wp-config.php.old" OR inurl:"wp-config.php.save"',
            # Server configuration backups
            'inurl:"httpd.conf.bak" OR inurl:"nginx.conf.bak" OR inurl:".htaccess.bak"',
            # Database dumps
            'ext:sql "INSERT INTO" "VALUES" ("password" OR "hash" OR "token")',
            # SSH keys accidentally exposed
            'inurl:"id_rsa" OR inurl:"id_dsa" ext:pub -github',
            # Exposed CSV/Excel with sensitive data
            'ext:csv "email" "password" OR ext:xlsx "credentials"',
        ]
    },
    "error_disclosure": {
        "severity": "medium",
        "description": "Error pages revealing stack traces and internal paths",
        "dorks": [
            # ASP.NET detailed errors
            '"Server Error in" "Application" "Stack Trace" "Version Information"',
            # Java/Spring stack traces
            '"java.lang.Exception" OR "org.springframework" "at line"',
            # Python/Django tracebacks
            '"Traceback (most recent call last)" "File" "line"',
            # Ruby on Rails error pages
            '"ActionController::RoutingError" OR "ActiveRecord::RecordNotFound"',
            # Node.js error stacks
            '"Error:" "at Object." "at Module."',
        ]
    }
}

# Simple fallback dorks (legacy format support)
DEFAULT_SIMPLE_DORKS = [
    'ext:log',
    'ext:env',
    'ext:sql',
    'ext:bak',
    'ext:conf',
    'inurl:admin',
    'inurl:api',
    'intitle:index.of'
]


class GoogleDorkTool(BaseTool):
    """
    Google Dorking using Programmable Search Engine API.

    Searches for sensitive files and interesting endpoints using
    targeted dork queries. Supports both simple dork lists and
    categorized dorks with severity levels.
    """

    def __init__(self, config: Dict):
        self.api_keys = config.get('api_keys', [])
        self.cx = config.get('cx', '')
        self.results_per_query = config.get('results_per_query', 10)
        self.request_interval = config.get('request_interval', 2)
        self.timeout = config.get('timeout', 30)

        # Support both legacy simple dorks and new categorized format
        dorks_config = config.get('dorks', {})

        if isinstance(dorks_config, dict) and 'categories' in dorks_config:
            # New categorized format
            self.use_categories = True
            self.dork_categories = self._load_categorized_dorks(dorks_config)
            # Flatten for total count
            self.dorks = []
            for cat_data in self.dork_categories.values():
                self.dorks.extend(cat_data['dorks'])
        elif isinstance(dorks_config, dict) and any(k in dorks_config for k in DORK_CATEGORIES):
            # Config specifies which built-in categories to use
            self.use_categories = True
            self.dork_categories = self._load_builtin_categories(dorks_config)
            self.dorks = []
            for cat_data in self.dork_categories.values():
                self.dorks.extend(cat_data['dorks'])
        elif isinstance(dorks_config, list):
            # Legacy simple list format
            self.use_categories = False
            self.dorks = dorks_config if dorks_config else DEFAULT_SIMPLE_DORKS
            self.dork_categories = {}
        else:
            # Default: use all built-in categories
            self.use_categories = True
            self.dork_categories = DORK_CATEGORIES.copy()
            self.dorks = []
            for cat_data in self.dork_categories.values():
                self.dorks.extend(cat_data['dorks'])

        if not self.api_keys:
            raise ValueError("No API keys configured")
        if not self.cx:
            raise ValueError("No Custom Search Engine ID (cx) configured")

        self.current_key_index = 0
        self.key_usage = {key: 0 for key in self.api_keys}

    def _load_categorized_dorks(self, config: Dict) -> Dict:
        """Load custom categorized dorks from config"""
        categories = {}
        for cat_name, cat_config in config.get('categories', {}).items():
            categories[cat_name] = {
                'severity': cat_config.get('severity', 'medium'),
                'description': cat_config.get('description', ''),
                'dorks': cat_config.get('dorks', [])
            }
        return categories

    def _load_builtin_categories(self, config: Dict) -> Dict:
        """Load specific built-in categories based on config"""
        categories = {}
        for cat_name in config.get('enabled_categories', list(DORK_CATEGORIES.keys())):
            if cat_name in DORK_CATEGORIES:
                categories[cat_name] = DORK_CATEGORIES[cat_name].copy()
        return categories

    def _get_dork_category(self, dork: str) -> Tuple[str, str, str]:
        """Get category info for a dork. Returns (category_name, severity, description)"""
        if not self.use_categories:
            return ('general', 'medium', 'General dork query')

        for cat_name, cat_data in self.dork_categories.items():
            if dork in cat_data['dorks']:
                return (cat_name, cat_data['severity'], cat_data['description'])

        return ('unknown', 'low', 'Uncategorized dork')

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
        """Extract findings from search results with category and severity info"""
        findings = []
        items = search_result.get('items', [])

        # Get category info for this dork
        category, severity, cat_description = self._get_dork_category(dork)

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
                'category': category,
                'severity': severity,
                'category_description': cat_description,
                'url': url,
                'path': parsed.path if 'parsed' in dir() else '',
                'title': title,
                'snippet': snippet[:300] if snippet else '',
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

        # Show category summary if using categorized dorks
        if self.use_categories:
            print(f"    [*] Using {len(self.dork_categories)} vulnerability categories:")
            for cat_name, cat_data in self.dork_categories.items():
                severity_badge = f"[{cat_data['severity'].upper()}]"
                print(f"        {severity_badge} {cat_name}: {len(cat_data['dorks'])} dorks")
            print(f"    [*] Total: {len(self.dorks)} specific dorks on {len(domains)} domain(s)")
        else:
            print(f"    [*] Running {len(self.dorks)} dorks on {len(domains)} domain(s)")

        print(f"    [*] Using {len(self.api_keys)} API key(s)")

        # Track findings by severity for summary
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for domain in domains:
            print(f"\n    [*] Dorking: {domain}")
            domain_findings = []
            current_category = None

            for dork in self.dorks:
                query_count += 1

                # Show category header when category changes
                if self.use_categories:
                    cat_name, severity, _ = self._get_dork_category(dork)
                    if cat_name != current_category:
                        current_category = cat_name
                        print(f"      [{severity.upper()}] {cat_name}")

                # Build the full query
                query = f"site:{domain} {dork}"

                # Truncate dork for display if too long
                display_dork = dork[:60] + "..." if len(dork) > 60 else dork
                print(f"        [{query_count}/{total_queries}] {display_dork}", end='', flush=True)

                result = self._search(query)

                if result:
                    total_results = result.get('searchInformation', {}).get('totalResults', '0')
                    items = result.get('items', [])

                    if items:
                        findings = self._extract_findings(result, domain, dork)
                        domain_findings.extend(findings)

                        # Count by severity
                        for _, meta in findings:
                            sev = meta.get('severity', 'medium')
                            severity_counts[sev] = severity_counts.get(sev, 0) + len(items)

                        print(f" -> {len(items)} results (total: {total_results})")
                    else:
                        print(f" -> 0 results")
                else:
                    print(f" -> error")

                # Rate limiting between requests
                time.sleep(self.request_interval)

            if domain_findings:
                print(f"    [+] {domain}: Found {len(domain_findings)} interesting results")
                all_findings.extend(domain_findings)

        # Print summary by severity
        print(f"\n    [*] Results by severity:")
        for sev in ['critical', 'high', 'medium', 'low']:
            if severity_counts.get(sev, 0) > 0:
                print(f"        [{sev.upper()}] {severity_counts[sev]} findings")

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
            Result dict with findings organized by severity and category
        """
        print(f"\n[GOOGLE DORK] Starting targeted dork search for {len(domains)} domain(s)")

        if self.use_categories:
            print(f"[GOOGLE DORK] Categories: {', '.join(self.dork_categories.keys())}")
            print(f"[GOOGLE DORK] Total dorks: {len(self.dorks)}")
        else:
            print(f"[GOOGLE DORK] Dorks: {len(self.dorks)}")

        detailed_results = {
            'timestamp': datetime.now().isoformat(),
            'domains': domains,
            'categories_used': list(self.dork_categories.keys()) if self.use_categories else [],
            'total_dorks': len(self.dorks),
            'findings_by_severity': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'findings_by_category': {},
            'findings_by_domain': {}
        }

        findings = self.run(domains)

        # Organize findings by severity, category, and domain
        for hostname, metadata in findings:
            finding_entry = {
                'hostname': hostname,
                'url': metadata.get('url', ''),
                'path': metadata.get('path', ''),
                'title': metadata.get('title', ''),
                'snippet': metadata.get('snippet', ''),
                'dork': metadata.get('dork', ''),
                'category': metadata.get('category', 'unknown'),
                'found_at': metadata.get('found_at', '')
            }

            # By severity
            severity = metadata.get('severity', 'medium')
            detailed_results['findings_by_severity'][severity].append(finding_entry)

            # By category
            category = metadata.get('category', 'unknown')
            if category not in detailed_results['findings_by_category']:
                detailed_results['findings_by_category'][category] = {
                    'severity': severity,
                    'description': metadata.get('category_description', ''),
                    'findings': []
                }
            detailed_results['findings_by_category'][category]['findings'].append(finding_entry)

            # By domain
            if hostname not in detailed_results['findings_by_domain']:
                detailed_results['findings_by_domain'][hostname] = []
            detailed_results['findings_by_domain'][hostname].append(finding_entry)

        # Summary stats
        detailed_results['summary'] = {
            'total_findings': len(findings),
            'unique_hosts': len(set(h for h, _ in findings)),
            'by_severity': {
                sev: len(items) for sev, items in detailed_results['findings_by_severity'].items()
            },
            'by_category': {
                cat: len(data['findings']) for cat, data in detailed_results['findings_by_category'].items()
            }
        }

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(detailed_results, f, indent=2)
            print(f"\n[GOOGLE DORK] Saved detailed results: {output_file}")

            # Print severity summary
            print(f"\n[GOOGLE DORK] === FINDINGS SUMMARY ===")
            for sev in ['critical', 'high', 'medium', 'low']:
                count = detailed_results['summary']['by_severity'].get(sev, 0)
                if count > 0:
                    print(f"  [{sev.upper()}] {count} finding(s)")
                    # Show first few URLs for critical/high
                    if sev in ['critical', 'high']:
                        for finding in detailed_results['findings_by_severity'][sev][:3]:
                            print(f"    -> {finding['url'][:80]}")

        return {
            'success': True,
            'total': len(findings),
            'unique_hosts': detailed_results['summary']['unique_hosts'],
            'by_severity': detailed_results['summary']['by_severity'],
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
