"""
LinkFinder Wrapper
Extracts endpoints from JavaScript files using LinkFinder
"""

import json
import re
import subprocess
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set


class LinkFinderWrapper:
    """Wrapper for LinkFinder tool"""

    def __init__(self, config: Dict):
        self.config = config
        self.path = config.get('path', 'linkfinder')
        self.enabled = config.get('enabled', True)
        self._verified = None
        self._linkfinder_cmd = None

    def is_available(self) -> bool:
        """Check if LinkFinder is installed and working"""
        if self._verified is not None:
            return self._verified

        # Try different ways to run LinkFinder
        commands_to_try = [
            # As Python module
            [sys.executable, '-m', 'linkfinder'],
            # Direct script (if in PATH)
            ['linkfinder'],
            # Python + linkfinder.py
            [sys.executable, 'linkfinder.py'],
            ['python', 'linkfinder.py'],
            ['python3', 'linkfinder.py'],
        ]

        # Also try to find linkfinder.py in common locations
        linkfinder_script = shutil.which('linkfinder.py')
        if linkfinder_script:
            commands_to_try.insert(0, [sys.executable, linkfinder_script])

        for cmd in commands_to_try:
            try:
                result = subprocess.run(
                    cmd + ['-h'],
                    capture_output=True,
                    timeout=10,
                    text=True
                )
                # Check if help output looks valid (not an error)
                if result.returncode == 0 or 'usage' in result.stdout.lower() or 'linkfinder' in result.stdout.lower():
                    self._verified = True
                    self._linkfinder_cmd = cmd
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue

        self._verified = False
        return False

    def analyze_file(self, file_path: Path, host: str = '') -> List[Dict]:
        """
        Analyze a single JS file with LinkFinder

        Returns list of endpoint dicts
        """
        endpoints = []

        if not self.enabled or not self.is_available():
            return endpoints

        try:
            # Run LinkFinder with the detected command
            cmd = self._linkfinder_cmd + ['-i', str(file_path), '-o', 'cli']

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(file_path.parent)  # Run from file's directory
            )

            # Parse output even if return code is non-zero (LinkFinder sometimes exits with errors but has output)
            if result.stdout:
                endpoints = self._parse_output(result.stdout, file_path, host)

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return endpoints

    def analyze_files(self, files: List[Path], file_to_host: Dict[str, str] = None) -> List[Dict]:
        """
        Analyze multiple JS files

        Args:
            files: List of JS file paths
            file_to_host: Optional mapping of filename -> host

        Returns deduplicated list of endpoint dicts
        """
        all_endpoints = []
        seen = set()
        file_to_host = file_to_host or {}

        for file_path in files:
            host = file_to_host.get(file_path.name, '')
            file_endpoints = self.analyze_file(file_path, host)

            for endpoint in file_endpoints:
                key = endpoint['endpoint']
                if key not in seen:
                    seen.add(key)
                    all_endpoints.append(endpoint)

        return all_endpoints

    def _parse_output(self, output: str, source_file: Path, host: str) -> List[Dict]:
        """Parse LinkFinder CLI output"""
        endpoints = []

        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Skip error messages and usage info
            if self._is_error_line(line):
                continue

            # Skip common false positives
            if self._is_false_positive(line):
                continue

            endpoint_type = self._classify_endpoint(line)

            endpoints.append({
                'endpoint': line,
                'type': endpoint_type,
                'source_file': source_file.name,
                'host': host,
                'tool': 'linkfinder'
            })

        return endpoints

    def _is_error_line(self, line: str) -> bool:
        """Check if line is an error message, not an endpoint"""
        error_indicators = [
            'usage:',
            'error:',
            'warning:',
            'traceback',
            'exception',
            'invalid input',
            'ssl error',
            'cannot find',
            'no such file',
            'permission denied',
            'linkfinder.py',
            'python',
            '-h for help',
            'options',
        ]
        line_lower = line.lower()
        return any(indicator in line_lower for indicator in error_indicators)

    def _classify_endpoint(self, endpoint: str) -> str:
        """Classify endpoint type"""
        if endpoint.startswith(('http://', 'https://', '//')):
            return 'url'
        elif '?' in endpoint or '&' in endpoint:
            return 'param'
        elif endpoint.startswith('/'):
            return 'path'
        elif re.match(r'^[a-zA-Z]+://', endpoint):
            return 'url'
        else:
            return 'path'

    def _is_false_positive(self, endpoint: str) -> bool:
        """Filter out common false positives"""
        fp_patterns = [
            r'^[0-9.]+$',  # Just numbers
            r'^[a-f0-9]{32,}$',  # Hashes
            r'^\s*$',  # Empty
            r'^[./]+$',  # Just dots/slashes
            r'^(true|false|null|undefined)$',  # JS keywords
            r'^[a-zA-Z]$',  # Single letter
            r'^\d+px$',  # CSS values
            r'^#[a-fA-F0-9]{3,6}$',  # Color codes
            r'^data:',  # Data URLs
            r'^javascript:',  # JavaScript URLs
            r'^\[object',  # Object strings
        ]

        for pattern in fp_patterns:
            if re.match(pattern, endpoint, re.IGNORECASE):
                return True

        # Too short
        if len(endpoint) < 2:
            return True

        # Common static assets we don't care about
        static_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.css']
        for ext in static_extensions:
            if endpoint.lower().endswith(ext):
                return True

        return False


class FallbackEndpointExtractor:
    """Fallback endpoint extraction using regex (when LinkFinder unavailable)"""

    ENDPOINT_PATTERNS = [
        # API paths
        r'["\'](/api/[^"\'>\s]+)["\']',
        r'["\'](/v[0-9]+/[^"\'>\s]+)["\']',
        r'["\'](/graphql[^"\'>\s]*)["\']',

        # Generic paths
        r'["\'](/[a-zA-Z][a-zA-Z0-9_/-]*)["\']',

        # Full URLs
        r'["\'](https?://[^"\'>\s]+)["\']',

        # WebSocket URLs
        r'["\'](wss?://[^"\'>\s]+)["\']',

        # Relative paths with query
        r'["\']([a-zA-Z0-9_/-]+\?[^"\'>\s]+)["\']',
    ]

    def __init__(self):
        self.patterns = [re.compile(p) for p in self.ENDPOINT_PATTERNS]

    def extract_from_file(self, file_path: Path, host: str = '') -> List[Dict]:
        """Extract endpoints from a JS file using regex"""
        endpoints = []
        seen = set()

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            for pattern in self.patterns:
                matches = pattern.findall(content)
                for match in matches:
                    if match not in seen and not self._is_false_positive(match):
                        seen.add(match)
                        endpoints.append({
                            'endpoint': match,
                            'type': self._classify(match),
                            'source_file': file_path.name,
                            'host': host,
                            'tool': 'regex'
                        })

        except Exception:
            pass

        return endpoints

    def extract_from_files(self, files: List[Path], file_to_host: Dict[str, str] = None) -> List[Dict]:
        """Extract endpoints from multiple files"""
        all_endpoints = []
        seen = set()
        file_to_host = file_to_host or {}

        for file_path in files:
            host = file_to_host.get(file_path.name, '')
            file_endpoints = self.extract_from_file(file_path, host)
            for ep in file_endpoints:
                if ep['endpoint'] not in seen:
                    seen.add(ep['endpoint'])
                    all_endpoints.append(ep)

        return all_endpoints

    def _classify(self, endpoint: str) -> str:
        if endpoint.startswith(('http://', 'https://', 'ws://', 'wss://')):
            return 'url'
        elif '?' in endpoint:
            return 'param'
        else:
            return 'path'

    def _is_false_positive(self, endpoint: str) -> bool:
        if len(endpoint) < 2:
            return True

        fp_patterns = [
            r'^[0-9.]+$',
            r'^[a-f0-9]{32,}$',
            r'^(true|false|null|undefined)$',
            r'^data:',
            r'^javascript:',
        ]

        for pattern in fp_patterns:
            if re.match(pattern, endpoint, re.IGNORECASE):
                return True

        static_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2']
        for ext in static_extensions:
            if endpoint.lower().endswith(ext):
                return True

        return False


def extract_endpoints(files: List[Path], config: Dict, file_to_host: Dict[str, str] = None) -> List[Dict]:
    """
    Extract endpoints from JS files

    Uses LinkFinder if available, falls back to regex extraction

    Args:
        files: List of JS file paths
        config: LinkFinder configuration
        file_to_host: Optional mapping of filename -> host

    Returns:
        List of endpoint dicts with host context
    """
    file_to_host = file_to_host or {}
    linkfinder = LinkFinderWrapper(config)

    if linkfinder.is_available():
        endpoints = linkfinder.analyze_files(files, file_to_host)

        # Also run fallback to catch anything LinkFinder misses
        fallback = FallbackEndpointExtractor()
        fallback_endpoints = fallback.extract_from_files(files, file_to_host)

        # Merge, preferring LinkFinder results
        seen = {ep['endpoint'] for ep in endpoints}
        for ep in fallback_endpoints:
            if ep['endpoint'] not in seen:
                endpoints.append(ep)

        return endpoints
    else:
        # Use fallback only
        fallback = FallbackEndpointExtractor()
        return fallback.extract_from_files(files, file_to_host)


def load_file_to_host_mapping(inventory_file: Path) -> Dict[str, str]:
    """Load file to host mapping from inventory.json"""
    mapping = {}

    if not inventory_file.exists():
        return mapping

    try:
        with open(inventory_file, 'r', encoding='utf-8') as f:
            inventory = json.load(f)

        for url, info in inventory.items():
            if info.get('status') == 'downloaded' and info.get('path'):
                filename = Path(info['path']).name
                host = info.get('host', '')
                if host:
                    mapping[filename] = host

    except Exception:
        pass

    return mapping
