"""
JavaScript Downloader Module
Downloads, deduplicates, and beautifies JavaScript files
"""

import hashlib
import json
import re
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Suppress SSL warnings for self-signed certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False


class JSDownloader:
    """Downloads and processes JavaScript files"""

    def __init__(self, config: Dict, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.js_dir = self.output_dir / 'js_files'

        self.timeout = config.get('timeout', 30)
        self.rate_limit = config.get('rate_limit', 2)
        self.max_file_size = config.get('max_file_size_mb', 10) * 1024 * 1024
        self.user_agents = config.get('user_agents', [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ])

        self._ua_index = 0
        self._last_request = 0

        # Hash tracking for deduplication
        self.hashes: Dict[str, str] = {}  # hash -> first file path
        self.inventory: Dict[str, Dict] = {}  # url -> file info

        # Create output directory
        self.js_dir.mkdir(parents=True, exist_ok=True)

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

    def download_all(self, js_files: Dict[str, List[Dict]]) -> Dict:
        """
        Download all discovered JS files

        Args:
            js_files: Dict mapping host -> list of JS file info dicts

        Returns:
            Download statistics dict
        """
        stats = {
            'total_urls': 0,
            'downloaded': 0,
            'deduplicated': 0,
            'failed': 0,
            'skipped_size': 0,
            'source_maps': 0
        }

        all_urls = []
        for host, files in js_files.items():
            for file_info in files:
                all_urls.append((host, file_info))

        stats['total_urls'] = len(all_urls)

        for host, file_info in all_urls:
            url = file_info.get('url', '')
            file_type = file_info.get('type', 'external')

            if not url:
                continue

            result = self.download_file(url, host, file_type)

            if result.get('success'):
                if result.get('deduplicated'):
                    stats['deduplicated'] += 1
                else:
                    stats['downloaded'] += 1
                    if file_type == 'sourcemap':
                        stats['source_maps'] += 1
            elif result.get('skipped_size'):
                stats['skipped_size'] += 1
            else:
                stats['failed'] += 1

        # Save inventory and hashes
        self._save_metadata()

        return stats

    def download_file(self, url: str, host: str, file_type: str = 'external') -> Dict:
        """
        Download a single JS file

        Returns dict with success status and file info
        """
        result = {
            'success': False,
            'url': url,
            'deduplicated': False,
            'skipped_size': False
        }

        # Skip if already processed
        if url in self.inventory:
            result['success'] = True
            result['deduplicated'] = True
            return result

        try:
            self._rate_limit_wait()

            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
            }

            # First, check content length with HEAD request
            try:
                head_response = requests.head(
                    url,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )

                content_length = head_response.headers.get('Content-Length')
                if content_length and int(content_length) > self.max_file_size:
                    result['skipped_size'] = True
                    self.inventory[url] = {
                        'status': 'skipped_size',
                        'size': int(content_length)
                    }
                    return result
            except:
                pass  # HEAD might not be supported, continue with GET

            # Download the file
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                stream=True
            )

            if response.status_code != 200:
                self.inventory[url] = {
                    'status': 'failed',
                    'status_code': response.status_code
                }
                return result

            # Check size from response
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > self.max_file_size:
                result['skipped_size'] = True
                self.inventory[url] = {
                    'status': 'skipped_size',
                    'size': int(content_length)
                }
                return result

            # Read content with size limit
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > self.max_file_size:
                    result['skipped_size'] = True
                    self.inventory[url] = {
                        'status': 'skipped_size',
                        'size': len(content)
                    }
                    return result

            # Calculate hash for deduplication
            content_hash = hashlib.sha256(content).hexdigest()

            # Check if we already have this content
            if content_hash in self.hashes:
                existing_path = self.hashes[content_hash]
                self.inventory[url] = {
                    'status': 'deduplicated',
                    'hash': content_hash,
                    'original': existing_path,
                    'host': host
                }
                result['success'] = True
                result['deduplicated'] = True
                return result

            # Decode content
            try:
                text_content = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    text_content = content.decode('latin-1')
                except:
                    text_content = content.decode('utf-8', errors='ignore')

            # Beautify if possible
            if HAS_JSBEAUTIFIER and file_type != 'sourcemap':
                try:
                    beautified = self._beautify_js(text_content)
                    if beautified:
                        text_content = beautified
                except:
                    pass  # Keep original if beautification fails

            # Determine file path
            file_path = self._get_file_path(url, host, file_type)

            # Save file
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(text_content)

            # Update tracking
            rel_path = str(file_path.relative_to(self.js_dir))
            self.hashes[content_hash] = rel_path
            self.inventory[url] = {
                'status': 'downloaded',
                'path': rel_path,
                'hash': content_hash,
                'size': len(content),
                'host': host,
                'type': file_type
            }

            result['success'] = True
            result['path'] = rel_path

            # Check for source map reference in JS content
            if file_type == 'external':
                map_url = self._extract_source_map_url(text_content, url)
                if map_url and map_url not in self.inventory:
                    # Queue source map for download
                    self.download_file(map_url, host, 'sourcemap')

            return result

        except requests.RequestException:
            self.inventory[url] = {'status': 'failed', 'error': 'request_error'}
            return result
        except Exception as e:
            self.inventory[url] = {'status': 'failed', 'error': str(e)[:100]}
            return result

    def _beautify_js(self, content: str) -> Optional[str]:
        """Beautify JavaScript content"""
        if not HAS_JSBEAUTIFIER:
            return None

        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.indent_with_tabs = False
        opts.preserve_newlines = True
        opts.max_preserve_newlines = 2
        opts.wrap_line_length = 0  # Don't wrap

        try:
            return jsbeautifier.beautify(content, opts)
        except:
            return None

    def _get_file_path(self, url: str, host: str, file_type: str) -> Path:
        """Generate local file path for URL"""
        parsed = urlparse(url)

        # Clean host for directory name
        clean_host = re.sub(r'[^\w.-]', '_', host)

        # Get filename from URL
        path_parts = parsed.path.strip('/').split('/')
        if path_parts and path_parts[-1]:
            filename = path_parts[-1]
        else:
            filename = 'index.js'

        # Clean filename
        filename = re.sub(r'[^\w.-]', '_', filename)

        # Ensure .js extension (except for source maps)
        if file_type == 'sourcemap':
            if not filename.endswith('.map'):
                filename += '.map'
        else:
            if not filename.endswith('.js'):
                filename += '.js'

        # Handle duplicates
        base_path = self.js_dir / clean_host / filename
        if base_path.exists():
            # Add hash suffix
            counter = 1
            stem = base_path.stem
            suffix = base_path.suffix
            while base_path.exists():
                base_path = self.js_dir / clean_host / f"{stem}_{counter}{suffix}"
                counter += 1

        return base_path

    def _extract_source_map_url(self, content: str, base_url: str) -> Optional[str]:
        """Extract sourceMappingURL from JS content"""
        patterns = [
            r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
            r'/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/',
        ]

        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                map_url = match.group(1).strip()

                # Skip data URLs
                if map_url.startswith('data:'):
                    return None

                # Resolve relative URL
                if not map_url.startswith(('http://', 'https://')):
                    if map_url.startswith('//'):
                        parsed = urlparse(base_url)
                        map_url = f"{parsed.scheme}:{map_url}"
                    else:
                        # Relative to base URL
                        from urllib.parse import urljoin
                        map_url = urljoin(base_url, map_url)

                return map_url

        return None

    def _save_metadata(self):
        """Save inventory and hash mappings"""
        inventory_file = self.js_dir / 'inventory.json'
        with open(inventory_file, 'w', encoding='utf-8') as f:
            json.dump(self.inventory, f, indent=2)

        hashes_file = self.js_dir / 'hashes.json'
        with open(hashes_file, 'w', encoding='utf-8') as f:
            json.dump(self.hashes, f, indent=2)

    def get_downloaded_files(self) -> List[Path]:
        """Get list of all downloaded JS files (not source maps)"""
        files = []

        for url, info in self.inventory.items():
            if info.get('status') == 'downloaded' and info.get('type') != 'sourcemap':
                path = self.js_dir / info['path']
                if path.exists():
                    files.append(path)

        return files

    def get_all_files(self) -> List[Path]:
        """Get list of all downloaded files including source maps"""
        files = []

        for url, info in self.inventory.items():
            if info.get('status') == 'downloaded':
                path = self.js_dir / info['path']
                if path.exists():
                    files.append(path)

        return files


def download_js_files(js_files: Dict[str, List[Dict]], config: Dict, output_dir: Path) -> Tuple[Dict, JSDownloader]:
    """
    Convenience function to download JS files

    Args:
        js_files: Dict mapping host -> list of JS file info
        config: Download configuration
        output_dir: Phase3 output directory

    Returns:
        Tuple of (stats dict, downloader instance)
    """
    downloader = JSDownloader(config, output_dir)
    stats = downloader.download_all(js_files)
    return stats, downloader
