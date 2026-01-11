"""
Custom JavaScript Analyzer
Context-aware secret detection, dangerous function patterns, and comment mining
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class JSAnalyzer:
    """Custom JavaScript analyzer for secrets, dangerous functions, and comments"""

    # Secret patterns with context awareness
    SECRET_PATTERNS = {
        # AWS
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'(?i)(aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',

        # API Keys - assignment patterns
        'api_key_assignment': r'(?i)["\']?(api[_-]?key|apikey|api_secret|api_token)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        'secret_assignment': r'(?i)["\']?(secret|secret_key|secretkey)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        'token_assignment': r'(?i)["\']?(access_token|auth_token|bearer_token|token)["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',

        # Auth
        'bearer_token': r'["\']Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']',
        'jwt_token': r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        'basic_auth': r'["\']Basic\s+[A-Za-z0-9+/=]{20,}["\']',

        # Private keys
        'private_key': r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE KEY-----',
        'private_key_inline': r'(?i)(private_key|privatekey|priv_key)\s*[:=]\s*["\']([^"\']{50,})["\']',

        # Password patterns
        'password_assignment': r'(?i)["\']?(password|passwd|pwd|pass)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
        'db_password': r'(?i)(db_password|database_password|mysql_password|postgres_password)\s*[:=]\s*["\']([^"\']+)["\']',

        # Service-specific
        'slack_webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
        'slack_token': r'xox[baprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+',
        'github_token': r'gh[pousr]_[A-Za-z0-9]{36,}',
        'firebase_url': r'https://[a-z0-9-]+\.firebaseio\.com',
        'firebase_api_key': r'AIza[0-9A-Za-z\-_]{35}',
        'google_oauth': r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com',
        'stripe_key': r'(?:sk|pk)_(test|live)_[A-Za-z0-9]{24,}',
        'twilio_sid': r'AC[a-f0-9]{32}',
        'sendgrid_key': r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
        'mailgun_key': r'key-[a-z0-9]{32}',
        'heroku_api': r'[hH]eroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',

        # URLs with credentials
        'url_with_creds': r'(?i)(https?://[^:]+:[^@]+@[^\s"\']+)',

        # Internal/staging URLs
        'internal_url': r'https?://[a-z0-9.-]*(internal|staging|dev|test|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[a-z0-9.-]*[:\d]*[/\w.-]*',
    }

    # Dangerous function patterns (designed for low false positives)
    DANGEROUS_PATTERNS = {
        'innerHTML_sink': {
            'pattern': r'\.innerHTML\s*=\s*[^"\'`;\n]',
            'description': 'innerHTML assignment with variable (potential DOM XSS)',
            'severity': 'HIGH'
        },
        'outerHTML_sink': {
            'pattern': r'\.outerHTML\s*=\s*[^"\'`;\n]',
            'description': 'outerHTML assignment with variable (potential DOM XSS)',
            'severity': 'HIGH'
        },
        'eval_dynamic': {
            'pattern': r'\beval\s*\(\s*[^"\'`\d\)]',
            'description': 'eval() with dynamic input (code injection)',
            'severity': 'HIGH'
        },
        'function_constructor': {
            'pattern': r'new\s+Function\s*\([^)]*[^"\'`]',
            'description': 'Function constructor with dynamic input',
            'severity': 'HIGH'
        },
        'document_write': {
            'pattern': r'document\.write\s*\(\s*[^"\'`]',
            'description': 'document.write with variable (DOM XSS)',
            'severity': 'MEDIUM'
        },
        'jquery_html': {
            'pattern': r'\$\([^)]+\)\.html\s*\(\s*[^"\'`\)]',
            'description': 'jQuery .html() with variable (DOM XSS)',
            'severity': 'HIGH'
        },
        'jquery_append': {
            'pattern': r'\$\([^)]+\)\.(append|prepend|after|before)\s*\(\s*[^"\'`\$\)]',
            'description': 'jQuery DOM manipulation with variable',
            'severity': 'MEDIUM'
        },
        'location_assign': {
            'pattern': r'(location\.href|location|window\.location)\s*=\s*[^"\'`;\n]',
            'description': 'Location assignment with variable (open redirect)',
            'severity': 'MEDIUM'
        },
        'location_replace': {
            'pattern': r'location\.replace\s*\(\s*[^"\'`]',
            'description': 'location.replace with variable (open redirect)',
            'severity': 'MEDIUM'
        },
        'postmessage_unsafe': {
            'pattern': r'\.postMessage\s*\([^,]+,\s*["\'][*]["\']',
            'description': 'postMessage with wildcard origin',
            'severity': 'HIGH'
        },
        'dangerously_set_html': {
            'pattern': r'dangerouslySetInnerHTML\s*=',
            'description': 'React dangerouslySetInnerHTML (review for XSS)',
            'severity': 'MEDIUM'
        },
        'script_src_dynamic': {
            'pattern': r'\.src\s*=\s*[^"\'`;\n].*\.js',
            'description': 'Dynamic script src assignment',
            'severity': 'MEDIUM'
        },
        'settimeout_string': {
            'pattern': r'setTimeout\s*\(\s*[^"\'`\(function]',
            'description': 'setTimeout with string (potential injection)',
            'severity': 'LOW'
        },
        'setinterval_string': {
            'pattern': r'setInterval\s*\(\s*[^"\'`\(function]',
            'description': 'setInterval with string (potential injection)',
            'severity': 'LOW'
        },
    }

    # Comment patterns for interesting findings
    COMMENT_PATTERNS = {
        'todo_fixme': {
            'pattern': r'(?://|/\*)\s*(TODO|FIXME|HACK|XXX|BUG|DEBUG|SECURITY|VULN|DANGER|WARNING|TEMP|TEMPORARY)[:\s]([^\n\r*]{0,200})',
            'type': 'dev_comment'
        },
        'credential_comment': {
            'pattern': r'(?://|/\*)[^\n\r]*(?:password|secret|key|token|credential|auth)[^\n\r]{0,100}',
            'type': 'credential_mention'
        },
        'admin_comment': {
            'pattern': r'(?://|/\*)[^\n\r]*(?:admin|root|superuser|backdoor|bypass)[^\n\r]{0,100}',
            'type': 'admin_mention'
        },
        'debug_comment': {
            'pattern': r'(?://|/\*)[^\n\r]*(?:debug|test|dev|staging|localhost)[^\n\r]{0,100}',
            'type': 'debug_mention'
        },
        'disabled_code': {
            'pattern': r'(?://|/\*)\s*(if\s*\(|return|function|const|let|var|await)[^\n\r]{0,150}',
            'type': 'disabled_code'
        },
    }

    def __init__(self):
        # Compile patterns for performance
        self.secret_patterns = {
            name: re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for name, pattern in self.SECRET_PATTERNS.items()
        }

        self.dangerous_patterns = {
            name: {
                'regex': re.compile(info['pattern'], re.MULTILINE),
                'description': info['description'],
                'severity': info['severity']
            }
            for name, info in self.DANGEROUS_PATTERNS.items()
        }

        self.comment_patterns = {
            name: {
                'regex': re.compile(info['pattern'], re.IGNORECASE | re.MULTILINE),
                'type': info['type']
            }
            for name, info in self.COMMENT_PATTERNS.items()
        }

    def analyze_file(self, file_path: Path) -> Dict:
        """
        Analyze a single JS file

        Returns dict with secrets, dangerous_functions, and comments
        """
        results = {
            'secrets': [],
            'dangerous_functions': [],
            'comments': [],
            'file': file_path.name
        }

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Find secrets
            results['secrets'] = self._find_secrets(content, file_path)

            # Find dangerous functions
            results['dangerous_functions'] = self._find_dangerous_functions(content, file_path)

            # Find interesting comments
            results['comments'] = self._find_comments(content, file_path)

        except Exception:
            pass

        return results

    def analyze_files(self, files: List[Path]) -> Dict:
        """
        Analyze multiple JS files

        Returns aggregated results dict
        """
        all_secrets = []
        all_dangerous = []
        all_comments = []

        seen_secrets = set()
        seen_dangerous = set()

        for file_path in files:
            results = self.analyze_file(file_path)

            # Dedupe secrets by value
            for secret in results['secrets']:
                key = (secret['type'], secret.get('value', '')[:50])
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    all_secrets.append(secret)

            # Dedupe dangerous by location
            for finding in results['dangerous_functions']:
                key = (finding['type'], finding['file'], finding.get('line', 0))
                if key not in seen_dangerous:
                    seen_dangerous.add(key)
                    all_dangerous.append(finding)

            # Comments - keep all
            all_comments.extend(results['comments'])

        return {
            'secrets': all_secrets,
            'dangerous_functions': all_dangerous,
            'comments': all_comments
        }

    def _find_secrets(self, content: str, file_path: Path) -> List[Dict]:
        """Find secrets with context awareness"""
        secrets = []
        lines = content.split('\n')

        for name, pattern in self.secret_patterns.items():
            for match in pattern.finditer(content):
                # Get line number
                line_num = content[:match.start()].count('\n') + 1

                # Get the matched value
                groups = match.groups()
                if groups:
                    # Use last non-None group (usually the actual secret)
                    value = next((g for g in reversed(groups) if g), match.group(0))
                else:
                    value = match.group(0)

                # Skip obvious false positives
                if self._is_secret_false_positive(value, name):
                    continue

                # Determine context confidence
                context = self._get_secret_context(content, match.start(), match.end())

                secrets.append({
                    'type': name,
                    'value': value[:100] + ('...' if len(value) > 100 else ''),
                    'file': file_path.name,
                    'line': line_num,
                    'context': context,
                    'tool': 'custom'
                })

        return secrets

    def _is_secret_false_positive(self, value: str, pattern_name: str) -> bool:
        """Check if a secret match is likely a false positive"""
        if not value:
            return True

        # Too short
        if len(value) < 8 and pattern_name not in ['password_assignment']:
            return True

        # Common placeholder values
        placeholders = [
            'your_', 'my_', 'test', 'demo', 'example', 'sample', 'placeholder',
            'xxx', 'aaa', 'bbb', '123', '000', 'changeme', 'replace', 'insert',
            'enter_', 'put_', 'add_', '<', '>', '${', '{{', 'process.env',
            'undefined', 'null', 'true', 'false', 'none', 'empty'
        ]

        value_lower = value.lower()
        for placeholder in placeholders:
            if placeholder in value_lower:
                return True

        # All same character
        if len(set(value.replace('-', '').replace('_', ''))) < 3:
            return True

        # Just numbers
        if value.isdigit():
            return True

        # ALL_CAPS constants (error messages, enum values)
        # Pattern: WORD or WORD_WORD or WORD_WORD_WORD
        if re.match(r'^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$', value):
            return True

        # URL paths being matched as tokens (starts with /)
        if value.startswith('/'):
            return True

        # Code snippets (contains newlines, semicolons, braces)
        if any(char in value for char in ['\n', ';', '{', '}', '()', 'function', 'return', '=>']):
            return True

        # OAuth flow names
        oauth_flows = ['passwordflow', 'clientcredentials', 'authorizationcode', 'implicit', 'refreshtoken']
        if value_lower.replace('_', '').replace('-', '') in oauth_flows:
            return True

        # Documentation URLs
        if 'docs.' in value_lower or 'documentation' in value_lower or 'readme' in value_lower:
            return True

        # Filtered/masked values
        if value in ['%filtered%', '[FILTERED]', '[REDACTED]', '***', '****']:
            return True

        # Common non-secret patterns
        non_secrets = [
            'invalid', 'expired', 'missing', 'required', 'error', 'failed',
            'forgot', 'reset', 'confirm', 'verify', 'login', 'logout',
            'success', 'pending', 'active', 'inactive', 'enabled', 'disabled'
        ]
        for ns in non_secrets:
            if value_lower.startswith(ns) or value_lower.endswith(ns):
                # Check if it looks like an error constant
                if '_' in value or value.isupper():
                    return True

        return False

    def _get_secret_context(self, content: str, start: int, end: int) -> str:
        """Determine confidence based on context"""
        # Get surrounding context
        context_start = max(0, start - 100)
        context_end = min(len(content), end + 100)
        context = content[context_start:context_end].lower()

        # HIGH confidence indicators
        high_indicators = [
            'config', 'secret', 'credential', 'auth', 'password',
            'key =', 'key:', 'token =', 'token:', 'api_key', 'apikey'
        ]

        for indicator in high_indicators:
            if indicator in context:
                return 'HIGH'

        # LOW confidence indicators (likely false positive)
        low_indicators = [
            'example', 'test', 'demo', 'sample', 'mock', 'fake',
            'placeholder', 'template', 'documentation', 'readme'
        ]

        for indicator in low_indicators:
            if indicator in context:
                return 'LOW'

        return 'MEDIUM'

    def _find_dangerous_functions(self, content: str, file_path: Path) -> List[Dict]:
        """Find dangerous function patterns"""
        findings = []

        for name, info in self.dangerous_patterns.items():
            for match in info['regex'].finditer(content):
                # Get line number
                line_num = content[:match.start()].count('\n') + 1

                # Get surrounding code for context
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                code_snippet = content[line_start:line_end].strip()[:200]

                # Additional false positive check
                if self._is_dangerous_false_positive(code_snippet, name):
                    continue

                findings.append({
                    'type': name,
                    'description': info['description'],
                    'severity': info['severity'],
                    'file': file_path.name,
                    'line': line_num,
                    'code': code_snippet,
                    'tool': 'custom'
                })

        return findings

    def _is_dangerous_false_positive(self, code: str, pattern_name: str) -> bool:
        """Check if dangerous function match is false positive"""
        code_lower = code.lower()

        # Skip if it's in a comment
        if code_lower.strip().startswith('//') or code_lower.strip().startswith('/*'):
            return True

        # Skip sanitized patterns
        sanitize_indicators = [
            'sanitize', 'escape', 'encode', 'purify', 'dompurify',
            'safe', 'clean', 'validate', 'filter'
        ]

        for indicator in sanitize_indicators:
            if indicator in code_lower:
                return True

        return False

    def _find_comments(self, content: str, file_path: Path) -> List[Dict]:
        """Find interesting comments"""
        comments = []

        for name, info in self.comment_patterns.items():
            for match in info['regex'].finditer(content):
                line_num = content[:match.start()].count('\n') + 1

                # Get the comment text
                comment_text = match.group(0).strip()

                # Skip very short comments
                if len(comment_text) < 10:
                    continue

                # Skip common non-interesting comments
                if self._is_boring_comment(comment_text):
                    continue

                comments.append({
                    'type': info['type'],
                    'text': comment_text[:300],
                    'file': file_path.name,
                    'line': line_num,
                    'pattern': name
                })

        return comments

    def _is_boring_comment(self, comment: str) -> bool:
        """Filter out common non-interesting comments"""
        boring_patterns = [
            r'^//\s*eslint',
            r'^//\s*@ts-',
            r'^//\s*prettier',
            r'^//\s*istanbul',
            r'^//\s*webpack',
            r'^//\s*babel',
            r'^/\*\s*\*/',
            r'^//\s*#\s*sourceMappingURL',
            r'^\s*\*\s*@(param|return|type|author|version)',
        ]

        for pattern in boring_patterns:
            if re.match(pattern, comment, re.IGNORECASE):
                return True

        return False


def analyze_js_files(files: List[Path]) -> Dict:
    """
    Analyze JS files for secrets, dangerous functions, and comments

    Args:
        files: List of JS file paths

    Returns:
        Dict with secrets, dangerous_functions, and comments lists
    """
    analyzer = JSAnalyzer()
    return analyzer.analyze_files(files)
