"""
Subdomain Takeover Detection
Detects potential subdomain takeover vulnerabilities using nuclei and subzy.

Primary: nuclei with takeover templates (74+ services)
Fallback: subzy (fingerprint-based detection)
"""

import subprocess
import json
import csv
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional


class TakeoverScanner:
    """
    Scans subdomains for takeover vulnerabilities.

    Prioritizes dead hosts and hosts with dangling CNAMEs as prime candidates.
    """

    def __init__(self, config: Dict):
        self.nuclei_path = config.get('nuclei_path', 'nuclei')
        self.subzy_path = config.get('subzy_path', 'subzy')
        self.threads = config.get('threads', 25)
        self.timeout = config.get('timeout', 10)
        self.use_nuclei = config.get('use_nuclei', True)
        self.use_subzy = config.get('use_subzy', True)

        # Check tool availability
        self.nuclei_available = self._check_tool(self.nuclei_path)
        self.subzy_available = self._check_tool(self.subzy_path)

    def _check_tool(self, tool_path: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run(
                [tool_path, '-version'],
                capture_output=True,
                timeout=10
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _load_candidates(self, project: Dict) -> Tuple[List[str], List[str]]:
        """
        Load takeover candidates from phase2 output.

        Returns:
            Tuple of (dead_hosts, live_hosts_with_cname)
        """
        phase2_dir = project['phases']['phase2']

        dead_hosts = []
        live_with_cname = []

        # Load dead hosts (prime candidates)
        dead_file = phase2_dir / 'dead.csv'
        if dead_file.exists():
            with open(dead_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    subdomain = row.get('subdomain', '').strip()
                    if subdomain and not subdomain.startswith('*.'):
                        dead_hosts.append(subdomain)

        # Load live hosts with CNAME records (potential dangling)
        live_file = phase2_dir / 'live.csv'
        if live_file.exists():
            with open(live_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    subdomain = row.get('subdomain', '').strip()
                    cname = row.get('cname', '').strip()
                    # Hosts with CNAME to third-party services are candidates
                    if subdomain and cname and not subdomain.startswith('*.'):
                        live_with_cname.append(subdomain)

        return dead_hosts, live_with_cname

    def _run_nuclei(self, targets: List[str], output_file: Path) -> List[Dict]:
        """Run nuclei with takeover templates"""
        if not self.nuclei_available or not self.use_nuclei:
            return []

        findings = []

        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            for target in targets:
                f.write(f"{target}\n")
            input_file = f.name

        try:
            cmd = [
                self.nuclei_path,
                '-l', input_file,
                '-t', 'http/takeovers/',
                '-c', str(self.threads),
                '-timeout', str(self.timeout),
                '-json',
                '-o', str(output_file),
                '-silent'
            ]

            print(f"    [*] Running nuclei with takeover templates...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 min max
            )

            # Parse JSON output
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                findings.append({
                                    'subdomain': data.get('host', ''),
                                    'service': data.get('template-id', '').replace('-', ' ').title(),
                                    'severity': data.get('info', {}).get('severity', 'unknown'),
                                    'matcher': data.get('matcher-name', ''),
                                    'tool': 'nuclei',
                                    'raw': data
                                })
                            except json.JSONDecodeError:
                                continue

            print(f"    [*] nuclei: {len(findings)} potential takeovers")

        except subprocess.TimeoutExpired:
            print(f"    [!] nuclei timed out")
        except Exception as e:
            print(f"    [!] nuclei error: {str(e)}")
        finally:
            Path(input_file).unlink(missing_ok=True)

        return findings

    def _run_subzy(self, targets: List[str], output_file: Path) -> List[Dict]:
        """Run subzy for fingerprint-based detection"""
        if not self.subzy_available or not self.use_subzy:
            return []

        findings = []

        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            for target in targets:
                f.write(f"{target}\n")
            input_file = f.name

        try:
            cmd = [
                self.subzy_path,
                'run',
                '--targets', input_file,
                '--concurrency', str(self.threads),
                '--timeout', str(self.timeout),
                '--hide_fails'
            ]

            print(f"    [*] Running subzy fingerprint detection...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            # Parse subzy output (format: [VULNERABLE] subdomain - service)
            for line in result.stdout.split('\n'):
                if '[VULNERABLE]' in line:
                    try:
                        parts = line.split('[VULNERABLE]')[1].strip()
                        if ' - ' in parts:
                            subdomain, service = parts.split(' - ', 1)
                        else:
                            subdomain = parts
                            service = 'Unknown'

                        findings.append({
                            'subdomain': subdomain.strip(),
                            'service': service.strip(),
                            'severity': 'high',
                            'matcher': 'fingerprint',
                            'tool': 'subzy',
                            'raw': line
                        })
                    except Exception:
                        continue

            print(f"    [*] subzy: {len(findings)} potential takeovers")

        except subprocess.TimeoutExpired:
            print(f"    [!] subzy timed out")
        except Exception as e:
            print(f"    [!] subzy error: {str(e)}")
        finally:
            Path(input_file).unlink(missing_ok=True)

        return findings

    def scan(self, project: Dict) -> Dict:
        """
        Run takeover scan on project targets.

        Returns:
            Result dict with findings
        """
        phase5_dir = project['phases']['phase5']
        phase5_dir.mkdir(parents=True, exist_ok=True)

        # Load candidates
        dead_hosts, live_with_cname = self._load_candidates(project)

        if not dead_hosts and not live_with_cname:
            return {
                'success': False,
                'error': 'No candidates found. Run resolve phase first.'
            }

        print(f"[TAKEOVER] Candidates: {len(dead_hosts)} dead, {len(live_with_cname)} with CNAME")

        # Combine candidates (dead hosts are priority)
        all_candidates = list(set(dead_hosts + live_with_cname))
        print(f"[TAKEOVER] Total unique targets: {len(all_candidates)}")

        # Check tool availability
        if not self.nuclei_available and not self.subzy_available:
            return {
                'success': False,
                'error': 'No takeover tools available. Install nuclei or subzy.'
            }

        if self.nuclei_available:
            print(f"[TAKEOVER] nuclei: available")
        else:
            print(f"[TAKEOVER] nuclei: not found (install from github.com/projectdiscovery/nuclei)")

        if self.subzy_available:
            print(f"[TAKEOVER] subzy: available")
        else:
            print(f"[TAKEOVER] subzy: not found (go install github.com/PentestPad/subzy@latest)")

        # Run scans
        all_findings = []

        # Run nuclei
        if self.nuclei_available and self.use_nuclei:
            nuclei_output = phase5_dir / 'nuclei_takeover.json'
            nuclei_findings = self._run_nuclei(all_candidates, nuclei_output)
            all_findings.extend(nuclei_findings)

        # Run subzy
        if self.subzy_available and self.use_subzy:
            subzy_output = phase5_dir / 'subzy_takeover.json'
            subzy_findings = self._run_subzy(all_candidates, subzy_output)
            all_findings.extend(subzy_findings)

        # Deduplicate by subdomain
        unique_findings = {}
        for finding in all_findings:
            key = finding['subdomain'].lower()
            if key not in unique_findings:
                unique_findings[key] = finding
            else:
                # Merge tools
                existing = unique_findings[key]
                if finding['tool'] not in existing.get('tools', [existing['tool']]):
                    existing['tools'] = existing.get('tools', [existing['tool']]) + [finding['tool']]

        findings_list = list(unique_findings.values())

        # Save results
        output_file = phase5_dir / 'takeovers.csv'
        self._save_results(findings_list, output_file)

        # Save metadata
        metadata = {
            'timestamp': datetime.now().isoformat(),
            'dead_hosts_checked': len(dead_hosts),
            'cname_hosts_checked': len(live_with_cname),
            'total_checked': len(all_candidates),
            'findings': len(findings_list),
            'tools_used': {
                'nuclei': self.nuclei_available and self.use_nuclei,
                'subzy': self.subzy_available and self.use_subzy
            }
        }

        with open(phase5_dir / 'takeover_metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        return {
            'success': True,
            'findings': len(findings_list),
            'output_file': str(output_file),
            'details': findings_list
        }

    def _save_results(self, findings: List[Dict], output_file: Path):
        """Save findings to CSV"""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = ['subdomain', 'service', 'severity', 'tool', 'matcher']

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(findings)

        print(f"[TAKEOVER] Saved: {output_file}")


def run(project: Dict) -> Dict:
    """
    Standalone runner for takeover module.
    Called via: python recon.py run <project> takeover
    """
    config = project['config'].get('vulns', {}).get('takeover', {})

    print(f"\n[TAKEOVER] Subdomain Takeover Detection")
    print(f"[TAKEOVER] Using nuclei templates + subzy fingerprints")

    try:
        scanner = TakeoverScanner(config)
        return scanner.scan(project)
    except Exception as e:
        return {'success': False, 'error': str(e)}
