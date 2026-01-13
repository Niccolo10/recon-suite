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


# =============================================================================
# EXPERT BUG BOUNTY DORK DATABASE
# =============================================================================
# These dorks are curated from:
# - Real P1/P2 bug bounty findings and disclosed reports
# - HackerOne/Bugcrowd disclosed vulnerabilities
# - Security research papers and conference talks
# - OWASP testing guides and cheat sheets
# - can-i-take-over-xyz and similar research projects
#
# Each category targets specific, exploitable misconfigurations with minimal
# false positives. Organized by attack surface and priority.
# =============================================================================

DORK_CATEGORIES = {
    # =========================================================================
    # CRITICAL SEVERITY - Immediate exploitation potential
    # =========================================================================

    "git_exposure": {
        "severity": "critical",
        "description": "Exposed .git directories - full source code disclosure via git-dumper",
        "dorks": [
            # Direct .git access patterns
            'inurl:"/.git/config" "[core]"',
            'inurl:"/.git/HEAD" "ref: refs"',
            'inurl:"/.git/index" filetype:index',
            'intitle:"Index of /.git" "objects"',
            # Common framework patterns
            'inurl:"/.git/logs/HEAD" "commit"',
            'inurl:".git/description" "Unnamed repository"',
        ]
    },

    "env_credentials": {
        "severity": "critical",
        "description": "Environment files with hardcoded secrets - direct credential theft",
        "dorks": [
            # Framework-specific env patterns
            'ext:env "DB_PASSWORD" OR "DATABASE_URL"',
            'ext:env "AWS_SECRET_ACCESS_KEY" OR "AWS_ACCESS_KEY_ID"',
            'ext:env "STRIPE_SECRET_KEY" OR "STRIPE_API_KEY"',
            'ext:env "SENDGRID_API_KEY" OR "MAILGUN_API_KEY"',
            'ext:env "TWILIO_AUTH_TOKEN" OR "TWILIO_SID"',
            'ext:env "GITHUB_TOKEN" OR "GITLAB_TOKEN"',
            'ext:env "JWT_SECRET" OR "SECRET_KEY"',
            'ext:env "REDIS_PASSWORD" OR "REDIS_URL"',
            # Docker/container secrets
            'ext:env "DOCKER_PASSWORD" OR "REGISTRY_PASSWORD"',
            'filetype:env "PRIVATE_KEY" OR "private_key"',
            # Directory listing of env files
            'intitle:"Index of" ".env.production"',
            'intitle:"Index of" ".env.local"',
            'intitle:"Index of" ".env.backup"',
        ]
    },

    "firebase_misconfig": {
        "severity": "critical",
        "description": "Firebase/Firestore with open read/write rules - data theft/manipulation",
        "dorks": [
            # Firebase database URLs (often misconfigured)
            'site:firebaseio.com "{domain_short}"',
            'site:firebaseapp.com "{domain_short}"',
            # Firebase config exposure
            '"apiKey" "authDomain" "databaseURL" "firebaseio.com"',
            'inurl:"firebaseio.com" ".json"',
            # Firestore patterns
            'site:firestore.googleapis.com "{domain_short}"',
        ]
    },

    "database_dumps": {
        "severity": "critical",
        "description": "Database exports with user data - PII exposure, credential theft",
        "dorks": [
            # SQL dumps with sensitive data
            'ext:sql "INSERT INTO" "users" "password"',
            'ext:sql "INSERT INTO" "admin" OR "INSERT INTO" "customers"',
            'ext:sql "CREATE TABLE" "credit_card" OR "payment"',
            # Backup patterns
            'intitle:"Index of" "backup.sql" OR "dump.sql"',
            'intitle:"Index of" ext:sql.gz OR ext:sql.bz2',
            'intitle:"Index of" "database" ext:tar.gz',
            # MongoDB exports
            'ext:json "email" "password" "salt"',
            'intitle:"Index of" "mongodump" OR "mongodb"',
        ]
    },

    "jwt_oauth_secrets": {
        "severity": "critical",
        "description": "JWT secrets and OAuth credentials - account takeover potential",
        "dorks": [
            # JWT secrets in config
            'ext:json "jwt_secret" OR "jwtSecret"',
            'ext:yml "jwt" "secret"',
            'ext:yaml "jwt_secret_key"',
            # OAuth credentials
            'ext:json "client_secret" "client_id"',
            'ext:json "oauth" "secret" OR "token"',
            '"OAUTH_CLIENT_SECRET" ext:env OR ext:yml',
            # Google OAuth
            'ext:json "installed" "client_secret" "client_id" "project_id"',
            # Service account keys (P1)
            'ext:json "type" "service_account" "private_key"',
        ]
    },

    "api_keys_exposed": {
        "severity": "critical",
        "description": "Hardcoded API keys in accessible files - service abuse potential",
        "dorks": [
            # Payment processors
            '"sk_live_" ext:js OR ext:json OR ext:txt',
            '"pk_live_" "sk_live_"',
            '"rk_live_" ext:js',
            # Cloud providers
            '"AKIA" ext:js OR ext:json',  # AWS access key prefix
            '"AIza" ext:js OR ext:json',  # Google API key prefix
            # Messaging services
            '"xoxb-" OR "xoxp-"',  # Slack tokens
            '"SG." ext:js OR ext:json',  # SendGrid
            # Maps and services
            '"maps.googleapis.com" "key="',
            '"api.mapbox.com" "access_token="',
        ]
    },

    # =========================================================================
    # HIGH SEVERITY - Significant security impact
    # =========================================================================

    "spring_actuator": {
        "severity": "high",
        "description": "Spring Boot Actuator endpoints - heapdump, env vars, RCE potential",
        "dorks": [
            # Critical actuator endpoints
            'inurl:"/actuator/heapdump"',
            'inurl:"/actuator/env" "spring"',
            'inurl:"/actuator/configprops"',
            'inurl:"/actuator/mappings"',
            # Gateway patterns (often leads to SSRF)
            'inurl:"/actuator/gateway/routes"',
            # Jolokia (RCE via JMX)
            'inurl:"/actuator/jolokia"',
            'inurl:"/jolokia/list"',
            # Old-style endpoints
            'inurl:"/manage/env"',
            'inurl:"/manage/heapdump"',
        ]
    },

    "debug_endpoints": {
        "severity": "high",
        "description": "Framework debug panels - source code, credentials, SSRF",
        "dorks": [
            # PHP
            'intitle:"phpinfo()" "PHP Version" "Configuration"',
            'inurl:"info.php" "phpinfo"',
            # Laravel
            'intitle:"Laravel Telescope" "Requests"',
            'inurl:"/_debugbar/open"',
            'intitle:"Whoops" "Stack Trace"',
            # Symfony
            'intitle:"Symfony Profiler" OR inurl:"/_profiler"',
            'inurl:"/_wdt/"',
            # Django
            'intitle:"Django" "DEBUG = True" "Traceback"',
            'inurl:"/__debug__/"',
            # Rails
            'intitle:"Action Controller: Exception caught"',
            'inurl:"/rails/info/properties"',
            # ASP.NET
            'intitle:"Server Error" "ASP.NET" "Stack Trace"',
            '"YSOD" "Yellow Screen of Death"',
            # Node.js
            'inurl:"/debug" "socket.io"',
            '"pm2" "Process Manager"',
        ]
    },

    "graphql_introspection": {
        "severity": "high",
        "description": "GraphQL introspection enabled - full API schema disclosure",
        "dorks": [
            # GraphQL IDEs
            'inurl:"/graphql" intitle:"GraphQL Playground"',
            'inurl:"/graphiql" intitle:"GraphiQL"',
            'inurl:"/altair" "GraphQL"',
            'inurl:"/graphql-explorer"',
            # Introspection patterns
            'inurl:"/graphql" "__schema"',
            'inurl:"/graphql/console"',
            # Apollo
            'inurl:"/graphql" "apollographql-client"',
            '"graphql" "introspectionQuery" ext:json',
        ]
    },

    "swagger_openapi": {
        "severity": "high",
        "description": "Swagger/OpenAPI docs - internal API endpoint discovery",
        "dorks": [
            # Swagger UI
            'inurl:"/swagger-ui.html" OR inurl:"/swagger-ui/"',
            'inurl:"/api-docs" "swagger"',
            'inurl:"/swagger.json" OR inurl:"/swagger.yaml"',
            # OpenAPI
            'inurl:"/openapi.json" OR inurl:"/openapi.yaml"',
            'inurl:"/v3/api-docs"',
            # Redoc
            'inurl:"/redoc" "ReDoc"',
            # Internal APIs often exposed
            'inurl:"/api/swagger"',
            'inurl:"/internal/swagger"',
            'inurl:"/private/api-docs"',
        ]
    },

    "admin_consoles": {
        "severity": "high",
        "description": "Admin panels with weak/no auth - complete system compromise",
        "dorks": [
            # CI/CD
            'intitle:"Dashboard [Jenkins]"',
            'intitle:"GitLab" inurl:"/admin"',
            '"Travis CI" inurl:"/admin"',
            # Databases
            'intitle:"Adminer" inurl:"adminer"',
            'intitle:"phpMyAdmin" "Welcome to phpMyAdmin"',
            'intitle:"pgAdmin" "pgAdmin 4"',
            'intitle:"MongoDB Compass"',
            # Monitoring
            'intitle:"Grafana" inurl:"/login" -site:grafana.com',
            'intitle:"Kibana" inurl:"/app"',
            'intitle:"Prometheus" inurl:"/targets"',
            # Infrastructure
            'intitle:"Kubernetes Dashboard"',
            'intitle:"Rancher" "Clusters"',
            'intitle:"Portainer" "Containers"',
            # Queues/Cache
            'intitle:"RabbitMQ Management"',
            'intitle:"Redis Commander"',
            '"bull-board" "queues"',
        ]
    },

    "backup_files": {
        "severity": "high",
        "description": "Backup files with source code or credentials",
        "dorks": [
            # Config backups
            'ext:bak "password" OR "secret" OR "key"',
            'ext:old "config" "database"',
            'ext:backup "password"',
            'inurl:".bak" "database" OR "config"',
            # CMS specific
            'inurl:"wp-config.php.bak" OR inurl:"wp-config.php.old"',
            'inurl:"web.config.bak" OR inurl:"web.config.old"',
            'inurl:"config.php.bak" "password"',
            # Archive backups
            'intitle:"Index of" "backup" ext:zip',
            'intitle:"Index of" "backup" ext:tar.gz',
            'intitle:"Index of" ext:7z "www"',
            # Editor backups
            'ext:swp "password"',  # vim swap
            'inurl:"~" ext:php',  # emacs backup
        ]
    },

    "cicd_secrets": {
        "severity": "high",
        "description": "CI/CD configs with secrets - pipeline compromise, credential theft",
        "dorks": [
            # GitHub
            'site:github.com "{domain}" ".github/workflows" "secrets"',
            'site:github.com "{domain}" "GITHUB_TOKEN" OR "GH_TOKEN"',
            '"github.com/{domain_short}" ".env" password',
            # GitLab
            'site:gitlab.com "{domain}" ".gitlab-ci.yml" "variables"',
            # Jenkins
            '"Jenkinsfile" "{domain}" "credentials"',
            'site:github.com "{domain}" "withCredentials"',
            # Docker
            'site:github.com "{domain}" "DOCKER_PASSWORD"',
            '"docker-compose" "{domain}" "password"',
            # Terraform
            'site:github.com "{domain}" "terraform" "secret_key"',
            'ext:tf "aws_secret_access_key"',
        ]
    },

    "kubernetes_exposure": {
        "severity": "high",
        "description": "Kubernetes configs and dashboards - cluster takeover potential",
        "dorks": [
            # Kubeconfig files
            'ext:yaml "clusters" "server" "certificate-authority-data"',
            'intitle:"Index of" "kubeconfig"',
            '"kubectl" "config" ext:yaml',
            # K8s secrets
            'ext:yaml "kind: Secret" "data"',
            'ext:yaml "apiVersion" "stringData" "password"',
            # Dashboard
            'intitle:"Kubernetes Dashboard" "namespace"',
            'inurl:"/api/v1/namespaces"',
            # Helm
            'ext:yaml "helm" "values" "password"',
            '"Chart.yaml" "{domain_short}"',
        ]
    },

    "log_exposure": {
        "severity": "high",
        "description": "Log files with credentials and session tokens",
        "dorks": [
            # Auth logs
            'ext:log "password" "authentication"',
            'ext:log "Authorization: Bearer"',
            'ext:log "session_id" OR "PHPSESSID"',
            'ext:log "API-Key" OR "api_key"',
            # Application logs
            'intitle:"Index of" "debug.log" OR "application.log"',
            'intitle:"Index of" "laravel.log"',
            'intitle:"Index of" "npm-debug.log"',
            # Access logs with queries
            'ext:log "POST" "password=" OR "passwd="',
            'ext:log "token=" "api"',
        ]
    },

    # =========================================================================
    # MEDIUM SEVERITY - Requires chaining or limited impact
    # =========================================================================

    "source_maps": {
        "severity": "medium",
        "description": "JavaScript source maps - full unminified source code",
        "dorks": [
            # Direct source map files
            'ext:map "version" "sources" "mappings"',
            'inurl:".js.map" "webpack"',
            'inurl:".min.js.map"',
            # Inline sourcemap references
            '"sourceMappingURL=" ext:js',
            'intitle:"Index of" ext:map',
        ]
    },

    "ssrf_indicators": {
        "severity": "medium",
        "description": "URL fetch functionality - potential SSRF entry points",
        "dorks": [
            # URL parameter patterns
            'inurl:"url=" "http"',
            'inurl:"fetch=" OR inurl:"load="',
            'inurl:"proxy=" OR inurl:"redirect="',
            'inurl:"imageUrl=" OR inurl:"imgUrl="',
            'inurl:"target=" "http"',
            # Webhook patterns
            'inurl:"webhook" "url"',
            'inurl:"callback=" "http"',
            # PDF generators (common SSRF)
            'inurl:"pdf" "url=" OR "link="',
            '"wkhtmltopdf" OR "puppeteer" inurl:"url="',
        ]
    },

    "open_redirect": {
        "severity": "medium",
        "description": "Open redirect parameters - OAuth token theft, phishing",
        "dorks": [
            # OAuth patterns
            'inurl:"redirect_uri=" OR inurl:"redirect_url="',
            'inurl:"return=" OR inurl:"return_to="',
            'inurl:"next=" OR inurl:"continue="',
            'inurl:"goto=" OR inurl:"dest="',
            'inurl:"redir=" OR inurl:"out="',
            # Login flows
            'inurl:"login" "redirect=" OR "next="',
            'inurl:"auth" "callback="',
        ]
    },

    "internal_paths": {
        "severity": "medium",
        "description": "Error pages revealing internal paths and structure",
        "dorks": [
            # Stack traces
            '"Exception" "at /home/" OR "at /var/"',
            '"Traceback" "/usr/local/" OR "/opt/"',
            '"Error" "C:\\Users\\" OR "C:\\inetpub\\"',
            # Framework errors
            '"Stack Trace" "in /app/" OR "in /src/"',
            '"Fatal error" "in /var/www/"',
            # Debug info
            '"Debug" "DocumentRoot" OR "SCRIPT_FILENAME"',
        ]
    },

    "version_disclosure": {
        "severity": "medium",
        "description": "Version information for vulnerability mapping",
        "dorks": [
            # Server headers in responses
            'inurl:"/server-status" "Apache"',
            'inurl:"/nginx_status"',
            # Common version pages
            '"php" "version" inurl:"info.php"',
            'inurl:"/version" "build" ext:json',
            '"X-Powered-By" "PHP" OR "ASP.NET"',
        ]
    },

    "directory_listing": {
        "severity": "medium",
        "description": "Open directory listings - sensitive file discovery",
        "dorks": [
            # Sensitive directories
            'intitle:"Index of /backup"',
            'intitle:"Index of /admin"',
            'intitle:"Index of /config"',
            'intitle:"Index of /uploads"',
            'intitle:"Index of /private"',
            'intitle:"Index of /internal"',
            # File types
            'intitle:"Index of" ext:sql OR ext:bak',
            'intitle:"Index of" ext:pem OR ext:key',
            'intitle:"Index of" "wp-content/uploads"',
        ]
    },

    # =========================================================================
    # EXTERNAL SOURCES - Third-party leaks
    # =========================================================================

    "github_leaks": {
        "severity": "critical",
        "description": "Credentials leaked in GitHub repositories",
        "dorks": [
            # Domain-specific secrets
            'site:github.com "://{domain}" "password" OR "secret"',
            'site:github.com "@{domain}" "api_key" OR "apikey"',
            'site:github.com "{domain}" "AWS_SECRET_ACCESS_KEY"',
            'site:github.com "{domain}" "PRIVATE_KEY" OR "private_key"',
            'site:github.com "{domain}" "client_secret"',
            # Internal configs
            'site:github.com "{domain}" ".env" "DB_PASSWORD"',
            'site:github.com "{domain}" "jdbc:" "password"',
            # Service tokens
            'site:github.com "{domain}" "Bearer " "token"',
            'site:github.com "{domain}" "Authorization"',
        ]
    },

    "cloud_storage": {
        "severity": "critical",
        "description": "Exposed cloud storage buckets with target data",
        "dorks": [
            # AWS S3
            'site:s3.amazonaws.com "{domain_short}"',
            'site:s3-*.amazonaws.com "{domain_short}"',
            '"s3.amazonaws.com/{domain_short}"',
            # Azure Blob
            'site:blob.core.windows.net "{domain_short}"',
            '"{domain_short}.blob.core.windows.net"',
            # Google Cloud Storage
            'site:storage.googleapis.com "{domain_short}"',
            '"{domain_short}.storage.googleapis.com"',
            # DigitalOcean Spaces
            'site:digitaloceanspaces.com "{domain_short}"',
        ]
    },

    "paste_sites": {
        "severity": "high",
        "description": "Credentials and configs on paste sites",
        "dorks": [
            # Pastebin
            'site:pastebin.com "@{domain}" "password"',
            'site:pastebin.com "://{domain}" "api_key"',
            'site:pastebin.com "{domain}" "database"',
            # Alternatives
            'site:paste.ee "{domain}"',
            'site:ghostbin.com "{domain}"',
            'site:controlc.com "{domain}"',
            'site:hastebin.com "{domain}"',
        ]
    },

    "project_management": {
        "severity": "high",
        "description": "Sensitive data in public project boards",
        "dorks": [
            # Trello
            'site:trello.com "{domain}" "password" OR "credentials"',
            'site:trello.com "{domain}" "api" "key" OR "secret"',
            'site:trello.com "{domain}" "staging" OR "production"',
            # Atlassian
            'site:*.atlassian.net "{domain}" "password"',
            'site:*.atlassian.net "{domain}" "credentials"',
            # Notion
            'site:notion.so "{domain}" "password" OR "secret"',
            'site:notion.site "{domain}"',
            # Confluence public
            '"confluence" "{domain}" "password" OR "api"',
        ]
    },

    "code_sharing": {
        "severity": "high",
        "description": "Code snippets with embedded secrets",
        "dorks": [
            # Code sharing sites
            'site:replit.com "{domain}"',
            'site:codepen.io "{domain}" "api"',
            'site:jsfiddle.net "{domain}"',
            'site:codesandbox.io "{domain}"',
            # Gist
            'site:gist.github.com "{domain}" "password"',
            'site:gist.github.com "{domain}" "secret"',
            # Bitbucket
            'site:bitbucket.org "{domain}" "password"',
            'site:gitlab.com "{domain}" ".env"',
        ]
    },

    "documentation_leaks": {
        "severity": "medium",
        "description": "Internal docs exposed publicly",
        "dorks": [
            # Documentation platforms
            'site:readme.io "{domain}" "api_key"',
            'site:gitbook.io "{domain}"',
            'site:readthedocs.io "{domain}"',
            # Wikis
            'site:*.atlassian.net/wiki "{domain}"',
            '"wiki" "{domain}" "internal" "password"',
            # Google Docs (public)
            'site:docs.google.com "{domain}" "password"',
            'site:drive.google.com "{domain}"',
        ]
    },
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
                # Handle placeholders for external site dorks
                if '{domain}' in dork or '{domain_short}' in dork:
                    # Extract short domain (e.g., "capital" from "capital.com")
                    domain_short = domain.split('.')[0]
                    query = dork.replace('{domain}', domain).replace('{domain_short}', domain_short)
                else:
                    # Normal dork - search within the target domain
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

        # Generate detailed report if output directory is set (called from passive runner)
        if hasattr(self, '_output_dir') and self._output_dir:
            self._save_dork_report(all_findings, domains)

        return all_findings

    def _save_dork_report(self, findings: List[Tuple[str, Dict]], domains: List[str]):
        """Save detailed dork findings to JSON and text report"""
        from pathlib import Path

        output_dir = Path(self._output_dir)
        output_file = output_dir / 'google_dork_findings.json'

        # Build detailed results structure
        detailed_results = {
            'timestamp': datetime.now().isoformat(),
            'domains': domains,
            'categories_used': list(self.dork_categories.keys()) if self.use_categories else [],
            'total_dorks': len(self.dorks),
            'findings_by_severity': {'critical': [], 'high': [], 'medium': [], 'low': []},
            'findings_by_category': {},
            'findings_by_domain': {}
        }

        # Organize findings
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
            'by_severity': {sev: len(items) for sev, items in detailed_results['findings_by_severity'].items()},
            'by_category': {cat: len(data['findings']) for cat, data in detailed_results['findings_by_category'].items()}
        }

        # Save JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(detailed_results, f, indent=2)

        # Save readable report
        report_file = str(output_file).replace('.json', '_report.txt')
        self._save_readable_report(detailed_results, report_file)

        print(f"    [*] Saved dork report: {output_file}")
        print(f"    [*] Saved readable report: {report_file}")

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

            # Also save a human-readable report
            report_file = output_file.replace('.json', '_report.txt')
            self._save_readable_report(detailed_results, report_file)
            print(f"[GOOGLE DORK] Saved readable report: {report_file}")

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

    def _save_readable_report(self, results: Dict, output_file: str):
        """Save a human-readable text report of findings"""
        lines = []
        lines.append("=" * 80)
        lines.append("GOOGLE DORK FINDINGS REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Generated: {results['timestamp']}")
        lines.append(f"Target domains: {', '.join(results['domains'])}")
        lines.append(f"Categories scanned: {len(results['categories_used'])}")
        lines.append(f"Total dorks used: {results['total_dorks']}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total findings: {results['summary']['total_findings']}")
        lines.append(f"Unique hosts: {results['summary']['unique_hosts']}")
        lines.append("")
        lines.append("By severity:")
        for sev in ['critical', 'high', 'medium', 'low']:
            count = results['summary']['by_severity'].get(sev, 0)
            if count > 0:
                lines.append(f"  [{sev.upper():8}] {count} finding(s)")
        lines.append("")

        # Group findings by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = results['findings_by_severity'].get(severity, [])
            if not findings:
                continue

            lines.append("")
            lines.append("=" * 80)
            lines.append(f"[{severity.upper()}] SEVERITY FINDINGS ({len(findings)} total)")
            lines.append("=" * 80)

            for i, finding in enumerate(findings, 1):
                lines.append("")
                lines.append(f"--- Finding #{i} ---")
                lines.append(f"Category: {finding.get('category', 'unknown')}")
                lines.append(f"Dork: {finding.get('dork', 'N/A')}")
                lines.append(f"URL: {finding.get('url', 'N/A')}")
                lines.append(f"Title: {finding.get('title', 'N/A')}")
                if finding.get('snippet'):
                    # Wrap snippet to 76 chars
                    snippet = finding['snippet']
                    lines.append(f"Snippet: {snippet[:200]}{'...' if len(snippet) > 200 else ''}")
                lines.append(f"Found: {finding.get('found_at', 'N/A')}")

        # Category breakdown
        lines.append("")
        lines.append("")
        lines.append("=" * 80)
        lines.append("FINDINGS BY CATEGORY")
        lines.append("=" * 80)

        for cat_name, cat_data in results.get('findings_by_category', {}).items():
            lines.append("")
            lines.append(f"[{cat_data.get('severity', 'unknown').upper()}] {cat_name}")
            lines.append(f"    {cat_data.get('description', '')}")
            lines.append(f"    Findings: {len(cat_data.get('findings', []))}")
            for finding in cat_data.get('findings', [])[:5]:
                lines.append(f"      - {finding.get('url', 'N/A')[:70]}")
            if len(cat_data.get('findings', [])) > 5:
                lines.append(f"      ... and {len(cat_data['findings']) - 5} more")

        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))


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
