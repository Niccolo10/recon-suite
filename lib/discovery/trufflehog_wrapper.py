"""
TruffleHog Wrapper
Detects secrets in JavaScript files using TruffleHog
"""

import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional


class TruffleHogWrapper:
    """Wrapper for TruffleHog secret scanner"""

    def __init__(self, config: Dict):
        self.config = config
        self.path = config.get('path', 'trufflehog')
        self.enabled = config.get('enabled', True)
        self._verified = None
        self._actual_path = None

    def is_available(self) -> bool:
        """Check if TruffleHog is installed and working"""
        if self._verified is not None:
            return self._verified

        # Try to find trufflehog
        paths_to_try = [
            self.path,
            'trufflehog',
            'trufflehog.exe',
        ]

        for path in paths_to_try:
            try:
                # Check if it exists
                found_path = shutil.which(path)
                if found_path:
                    # Verify it works
                    result = subprocess.run(
                        [found_path, '--version'],
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

    def scan_directory(self, directory: Path) -> List[Dict]:
        """
        Scan a directory for secrets using TruffleHog

        Returns list of finding dicts
        """
        findings = []

        if not self.enabled or not self.is_available():
            return findings

        try:
            cmd = [
                self._actual_path,
                'filesystem',
                str(directory),
                '--json',
                '--no-update',
                '--no-verification'  # Skip live verification for speed
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large directories
            )

            # TruffleHog outputs one JSON object per line
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        finding = self._parse_finding(data, directory)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return findings

    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a single file for secrets

        Returns list of finding dicts
        """
        findings = []

        if not self.enabled or not self.is_available():
            return findings

        try:
            cmd = [
                self._actual_path,
                'filesystem',
                str(file_path),
                '--json',
                '--no-update',
                '--no-verification'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        finding = self._parse_finding(data, file_path.parent)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return findings

    def _parse_finding(self, data: Dict, base_dir: Path) -> Optional[Dict]:
        """Parse TruffleHog JSON output into finding dict"""
        try:
            # Extract relevant fields
            detector_name = data.get('DetectorName', data.get('detectorName', 'unknown'))
            raw = data.get('Raw', data.get('raw', ''))

            # Get source metadata
            source_metadata = data.get('SourceMetadata', data.get('sourceMetadata', {}))
            data_section = source_metadata.get('Data', source_metadata.get('data', {}))
            filesystem = data_section.get('Filesystem', data_section.get('filesystem', {}))

            file_path = filesystem.get('file', '')
            line = filesystem.get('line', 0)

            # Make path relative to base_dir if possible
            if file_path:
                try:
                    file_path = str(Path(file_path).relative_to(base_dir))
                except ValueError:
                    pass

            # Get verification status
            verified = data.get('Verified', data.get('verified', False))

            # Skip if raw value is too short (likely false positive)
            if len(raw) < 8:
                return None

            return {
                'type': detector_name,
                'value': raw[:100] + ('...' if len(raw) > 100 else ''),  # Truncate long values
                'full_value': raw,
                'file': file_path,
                'line': line,
                'verified': verified,
                'tool': 'trufflehog',
                'context': 'HIGH' if verified else 'MEDIUM'
            }

        except Exception:
            return None


def scan_for_secrets(directory: Path, config: Dict) -> List[Dict]:
    """
    Scan directory for secrets using TruffleHog

    Args:
        directory: Directory containing JS files
        config: TruffleHog configuration

    Returns:
        List of secret finding dicts
    """
    wrapper = TruffleHogWrapper(config)

    if wrapper.is_available():
        return wrapper.scan_directory(directory)
    else:
        return []
