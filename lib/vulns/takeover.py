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


# CNAME patterns that indicate potentially vulnerable services
VULNERABLE_CNAME_PATTERNS = {
    # Cloud platforms
    'amazonaws.com': 'AWS S3/Elastic Beanstalk',
    'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
    's3.amazonaws.com': 'AWS S3',
    's3-website': 'AWS S3 Website',
    'cloudfront.net': 'AWS CloudFront',
    'azurewebsites.net': 'Azure App Service',
    'cloudapp.azure.com': 'Azure Cloud',
    'azure-api.net': 'Azure API Management',
    'azurecontainer.io': 'Azure Container',
    'azureedge.net': 'Azure CDN',
    'blob.core.windows.net': 'Azure Blob',
    'trafficmanager.net': 'Azure Traffic Manager',
    'herokuapp.com': 'Heroku',
    'herokudns.com': 'Heroku DNS',
    'firebaseapp.com': 'Firebase',
    'web.app': 'Firebase',
    'appspot.com': 'Google App Engine',
    # Website builders
    'squarespace.com': 'Squarespace',
    'ghost.io': 'Ghost',
    'wordpress.com': 'WordPress.com',
    'wpengine.com': 'WP Engine',
    'pantheon.io': 'Pantheon',
    'webflow.io': 'Webflow',
    'wixsite.com': 'Wix',
    'myshopify.com': 'Shopify',
    'shopifycloud.com': 'Shopify',
    'strikingly.com': 'Strikingly',
    'weebly.com': 'Weebly',
    'cargo.site': 'Cargo',
    # Git hosting
    'github.io': 'GitHub Pages',
    'githubusercontent.com': 'GitHub',
    'gitlab.io': 'GitLab Pages',
    'bitbucket.io': 'Bitbucket',
    'bitbucket.org': 'Bitbucket',
    # CDN & infrastructure
    'fastly.net': 'Fastly',
    'global.fastly.net': 'Fastly',
    'netlify.app': 'Netlify',
    'netlify.com': 'Netlify',
    'vercel.app': 'Vercel',
    'now.sh': 'Vercel (now.sh)',
    'surge.sh': 'Surge',
    'render.com': 'Render',
    'fly.dev': 'Fly.io',
    # Help desk & support
    'freshdesk.com': 'Freshdesk',
    'helpjuice.com': 'Helpjuice',
    'helpscoutdocs.com': 'HelpScout',
    'zendesk.com': 'Zendesk',
    'tawk.to': 'Tawk.to',
    'uservoice.com': 'UserVoice',
    'kayako.com': 'Kayako',
    # Marketing & landing pages
    'launchrock.com': 'Launchrock',
    'unbounce.com': 'Unbounce',
    'leadpages.net': 'Leadpages',
    'instapage.com': 'Instapage',
    'landingi.com': 'Landingi',
    # Status pages
    'statuspage.io': 'Statuspage',
    'status.io': 'Status.io',
    # Email & communication
    'mailgun.org': 'Mailgun',
    'sendgrid.net': 'SendGrid',
    'campaignmonitor.com': 'Campaign Monitor',
    # Misc SaaS
    'desk.com': 'Desk.com',
    'teamwork.com': 'Teamwork',
    'cargocollective.com': 'Cargo',
    'aha.io': 'Aha.io',
    'brightcove.com': 'Brightcove',
    'bigcartel.com': 'Big Cartel',
    'getresponse.com': 'GetResponse',
    'acquia-sites.com': 'Acquia',
    'proposify.biz': 'Proposify',
    'simplebooklet.com': 'SimpleBooklet',
    'tictail.com': 'Tictail',
    'smartling.com': 'Smartling',
    'aftership.com': 'AfterShip',
    'reamaze.com': 'Re:amaze',
    'readme.io': 'ReadMe',
    'smugmug.com': 'SmugMug',
    'feedpress.me': 'FeedPress',
    'anima.io': 'Anima',
    'pingdom.com': 'Pingdom',
    'canny.io': 'Canny',
    'ngrok.io': 'Ngrok',
    'airee.ru': 'Airee.ru',
    # DNS delegation issues
    'dnsdelegation.io': 'DNS Delegation',
}

# Fingerprints in page titles/content that indicate unclaimed domains
TAKEOVER_TITLE_FINGERPRINTS = [
    'domain not claimed',
    'there isn\'t a github pages site here',
    'no such app',
    'heroku | no such app',
    'this shop is unavailable',
    'project not found',
    'the specified bucket does not exist',
    'nosuchbucket',
    'site not found',
    'page not found',
    '404 not found',
    'bucket not found',
    'this site can\'t be reached',
    'fastly error: unknown domain',
    'there\'s nothing here, yet',
    'is not a registered instapage subdomain',
    'uh oh. that page doesn\'t exist',
    'this uservoice subdomain is currently available',
    'do you want to register',
    'help center closed',
    'company not found',
    'this azure websites/function app is stopped',
    'web app - unavailable',
]


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

    def _is_vulnerable_cname(self, cname: str) -> Tuple[bool, str]:
        """
        Check if a CNAME points to a potentially vulnerable service.

        Returns:
            Tuple of (is_vulnerable, service_name)
        """
        cname_lower = cname.lower()
        for pattern, service in VULNERABLE_CNAME_PATTERNS.items():
            if pattern in cname_lower:
                return True, service
        return False, ''

    def _has_takeover_fingerprint(self, title: str) -> bool:
        """Check if page title contains takeover fingerprints."""
        title_lower = title.lower()
        for fingerprint in TAKEOVER_TITLE_FINGERPRINTS:
            if fingerprint in title_lower:
                return True
        return False

    def _load_candidates(self, project: Dict) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Load takeover candidates from phase2 output.

        Returns:
            Tuple of (dead_hosts, vulnerable_cname_hosts, fingerprint_hosts)
        """
        phase2_dir = project['phases']['phase2']

        dead_hosts = []
        vulnerable_cname_hosts = []
        fingerprint_hosts = []

        # Load dead hosts (prime candidates - DNS resolves but no HTTP response)
        dead_file = phase2_dir / 'dead.csv'
        if dead_file.exists():
            with open(dead_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    subdomain = row.get('subdomain', '').strip()
                    if subdomain and not subdomain.startswith('*.'):
                        dead_hosts.append({
                            'subdomain': subdomain,
                            'reason': 'dead_host'
                        })

        # Load live hosts - check for vulnerable CNAMEs and takeover fingerprints
        live_file = phase2_dir / 'live.csv'
        if live_file.exists():
            with open(live_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    subdomain = row.get('subdomain', '').strip()
                    cname = row.get('cname', '').strip()
                    title = row.get('title', '').strip()
                    status_code = row.get('status_code', '').strip()

                    if not subdomain or subdomain.startswith('*.'):
                        continue

                    # Check 1: CNAME points to vulnerable service
                    if cname:
                        is_vulnerable, service = self._is_vulnerable_cname(cname)
                        if is_vulnerable:
                            vulnerable_cname_hosts.append({
                                'subdomain': subdomain,
                                'cname': cname,
                                'service': service,
                                'reason': 'vulnerable_cname'
                            })
                            continue  # Don't double-add

                    # Check 2: Title contains takeover fingerprint
                    if title and self._has_takeover_fingerprint(title):
                        fingerprint_hosts.append({
                            'subdomain': subdomain,
                            'title': title,
                            'cname': cname,
                            'reason': 'takeover_fingerprint'
                        })
                        continue

                    # Check 3: 404 status with CNAME to third-party (potential unclaimed)
                    if status_code == '404' and cname:
                        # More likely to be takeover if pointing to third-party
                        is_vulnerable, service = self._is_vulnerable_cname(cname)
                        if is_vulnerable:
                            vulnerable_cname_hosts.append({
                                'subdomain': subdomain,
                                'cname': cname,
                                'service': service,
                                'reason': 'vulnerable_cname_404'
                            })

        return dead_hosts, vulnerable_cname_hosts, fingerprint_hosts

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
        dead_hosts, vulnerable_cname_hosts, fingerprint_hosts = self._load_candidates(project)

        if not dead_hosts and not vulnerable_cname_hosts and not fingerprint_hosts:
            return {
                'success': False,
                'error': 'No candidates found. Run resolve phase first.'
            }

        print(f"[TAKEOVER] Candidates breakdown:")
        print(f"    Dead hosts (no HTTP response): {len(dead_hosts)}")
        print(f"    Vulnerable CNAME patterns: {len(vulnerable_cname_hosts)}")
        print(f"    Takeover fingerprints in title: {len(fingerprint_hosts)}")

        # Report high-priority fingerprint matches immediately
        if fingerprint_hosts:
            print(f"\n[TAKEOVER] HIGH PRIORITY - Hosts with takeover fingerprints:")
            for host in fingerprint_hosts:
                print(f"    {host['subdomain']} - Title: {host['title'][:60]}...")

        # Report vulnerable CNAME matches
        if vulnerable_cname_hosts:
            print(f"\n[TAKEOVER] Hosts with vulnerable CNAME patterns:")
            for host in vulnerable_cname_hosts:
                print(f"    {host['subdomain']} -> {host['service']} ({host['cname'][:50]})")

        # Combine all candidate subdomains for scanning
        all_subdomains = set()
        for h in dead_hosts:
            all_subdomains.add(h['subdomain'])
        for h in vulnerable_cname_hosts:
            all_subdomains.add(h['subdomain'])
        for h in fingerprint_hosts:
            all_subdomains.add(h['subdomain'])

        all_candidates = list(all_subdomains)
        print(f"\n[TAKEOVER] Total unique targets to scan: {len(all_candidates)}")

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
            'candidates': {
                'dead_hosts': len(dead_hosts),
                'vulnerable_cname': len(vulnerable_cname_hosts),
                'fingerprint_matches': len(fingerprint_hosts),
                'total_unique': len(all_candidates)
            },
            'findings': len(findings_list),
            'tools_used': {
                'nuclei': self.nuclei_available and self.use_nuclei,
                'subzy': self.subzy_available and self.use_subzy
            },
            'high_priority_hosts': [h['subdomain'] for h in fingerprint_hosts],
            'vulnerable_cname_details': [
                {'subdomain': h['subdomain'], 'service': h['service'], 'cname': h['cname']}
                for h in vulnerable_cname_hosts
            ]
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
