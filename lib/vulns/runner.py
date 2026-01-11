"""
Vulnerability Checks Runner - Phase 5
Orchestrates vulnerability detection modules.
"""

from typing import Dict
from .takeover import TakeoverScanner


def run_vulns(project: Dict) -> Dict:
    """
    Run vulnerability checks.

    Modules:
        - Subdomain takeover detection (nuclei + subzy)
        - Misconfiguration checks (coming soon)
    """
    print("\n[VULNS] Phase 5: Vulnerability Checks")

    total_findings = 0
    results = {}

    # Run takeover detection
    print("\n" + "=" * 50)
    print("[VULNS] Running subdomain takeover detection...")
    print("=" * 50)

    config = project['config'].get('vulns', {}).get('takeover', {})
    scanner = TakeoverScanner(config)
    takeover_result = scanner.scan(project)

    if takeover_result.get('success'):
        findings = takeover_result.get('findings', 0)
        total_findings += findings
        results['takeover'] = {
            'success': True,
            'findings': findings,
            'output': takeover_result.get('output_file', '')
        }

        if findings > 0:
            print(f"\n[VULNS] ALERT: {findings} potential subdomain takeover(s) found!")
            print(f"[VULNS] Review: {takeover_result.get('output_file', '')}")
    else:
        error = takeover_result.get('error', 'Unknown error')
        print(f"[VULNS] Takeover check failed: {error}")
        results['takeover'] = {'success': False, 'error': error}

    # Misconfiguration checks (placeholder)
    print("\n" + "=" * 50)
    print("[VULNS] Misconfiguration checks: coming soon")
    print("  - CORS misconfigurations")
    print("  - Exposed files (.git, .env, etc.)")
    print("  - Security headers")
    print("=" * 50)

    return {
        'success': True,
        'findings': total_findings,
        'results': results
    }
