"""
Gowitness Wrapper
Takes screenshots of live hosts in the background
"""

import subprocess
import shutil
import tempfile
import csv
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class GowitnessRunner:
    """Wrapper for gowitness screenshot tool"""

    def __init__(self, config: Dict):
        self.config = config
        self.path = config.get('gowitness_path', 'gowitness')
        self.threads = config.get('gowitness_threads', 10)
        self.timeout = config.get('gowitness_timeout', 10)
        self.enabled = config.get('gowitness_enabled', True)
        self._verified = None
        self._actual_path = None

    def is_available(self) -> bool:
        """Check if gowitness is installed"""
        if self._verified is not None:
            return self._verified

        paths_to_try = [
            self.path,
            'gowitness',
            'gowitness.exe',
        ]

        for path in paths_to_try:
            try:
                found_path = shutil.which(path)
                if found_path:
                    result = subprocess.run(
                        [found_path, 'version'],
                        capture_output=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        self._verified = True
                        self._actual_path = found_path
                        return True
            except:
                continue

        self._verified = False
        return False

    def run_screenshots(self, live_csv: Path, output_dir: Path, background: bool = True) -> Dict:
        """
        Run gowitness on live hosts

        Args:
            live_csv: Path to phase2/live.csv
            output_dir: Directory to store screenshots
            background: If True, run in background and return immediately

        Returns:
            Dict with status and process info
        """
        if not self.enabled:
            return {'success': False, 'error': 'gowitness disabled in config'}

        if not self.is_available():
            return {'success': False, 'error': 'gowitness not found'}

        if not live_csv.exists():
            return {'success': False, 'error': f'live.csv not found: {live_csv}'}

        # Create output directory
        screenshots_dir = output_dir / 'screenshots'
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        # Extract URLs from live.csv
        urls = self._extract_urls(live_csv)
        if not urls:
            return {'success': False, 'error': 'No URLs found in live.csv'}

        # Write URLs to temp file
        urls_file = screenshots_dir / 'urls.txt'
        with open(urls_file, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(f"{url}\n")

        # Build gowitness command
        csv_file = screenshots_dir / 'gowitness.csv'

        cmd = [
            self._actual_path,
            'scan', 'file',
            '-f', str(urls_file),
            '--write-db',
            '--write-csv',
            '--write-csv-file', str(csv_file),
            '--screenshot-path', str(screenshots_dir),
            '--threads', str(self.threads),
            '--timeout', str(self.timeout),
        ]

        try:
            if background:
                # Run in background
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(screenshots_dir)
                )

                # Save process info
                info_file = screenshots_dir / 'gowitness_process.txt'
                with open(info_file, 'w') as f:
                    f.write(f"PID: {process.pid}\n")
                    f.write(f"Started: {datetime.now().isoformat()}\n")
                    f.write(f"URLs: {len(urls)}\n")
                    f.write(f"Command: {' '.join(cmd)}\n")

                return {
                    'success': True,
                    'background': True,
                    'pid': process.pid,
                    'urls_count': len(urls),
                    'output_dir': str(screenshots_dir)
                }
            else:
                # Run and wait
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(screenshots_dir),
                    timeout=3600  # 1 hour max
                )

                return {
                    'success': result.returncode == 0,
                    'background': False,
                    'urls_count': len(urls),
                    'output_dir': str(screenshots_dir),
                    'returncode': result.returncode
                }

        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'gowitness timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _extract_urls(self, live_csv: Path) -> List[str]:
        """Extract URLs from live.csv"""
        urls = []
        seen = set()

        try:
            with open(live_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = row.get('url', '').strip()
                    if url and url not in seen:
                        seen.add(url)
                        urls.append(url)
        except Exception:
            pass

        return urls

    def check_status(self, screenshots_dir: Path) -> Dict:
        """Check status of gowitness run"""
        info_file = screenshots_dir / 'gowitness_process.txt'
        csv_file = screenshots_dir / 'gowitness.csv'
        db_file = screenshots_dir / 'gowitness.sqlite3'

        status = {
            'running': False,
            'completed': False,
            'screenshots_count': 0,
            'csv_exists': csv_file.exists(),
            'db_exists': db_file.exists()
        }

        # Count screenshots (can be png or jpeg)
        if screenshots_dir.exists():
            screenshots = list(screenshots_dir.glob('*.png')) + list(screenshots_dir.glob('*.jpeg')) + list(screenshots_dir.glob('*.jpg'))
            status['screenshots_count'] = len(screenshots)

        # Check if process info exists
        if info_file.exists():
            with open(info_file, 'r') as f:
                content = f.read()
                if 'PID:' in content:
                    try:
                        pid = int(content.split('PID:')[1].split('\n')[0].strip())
                        # Check if process is still running
                        import os
                        try:
                            os.kill(pid, 0)
                            status['running'] = True
                        except OSError:
                            status['running'] = False
                            status['completed'] = True
                    except:
                        pass

        # If CSV exists and has content, consider it completed
        if csv_file.exists() and csv_file.stat().st_size > 0:
            status['completed'] = True

        return status


def run_gowitness_background(live_csv: Path, output_dir: Path, config: Dict) -> Dict:
    """
    Convenience function to run gowitness in background

    Args:
        live_csv: Path to live.csv
        output_dir: Phase2 directory
        config: Tool configuration

    Returns:
        Status dict
    """
    runner = GowitnessRunner(config)
    return runner.run_screenshots(live_csv, output_dir, background=True)


def check_gowitness_status(phase2_dir: Path) -> Dict:
    """Check gowitness status for a project"""
    screenshots_dir = phase2_dir / 'screenshots'
    runner = GowitnessRunner({})
    return runner.check_status(screenshots_dir)
