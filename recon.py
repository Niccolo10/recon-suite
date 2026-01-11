#!/usr/bin/env python3
"""
Recon Suite - Unified Bug Bounty Reconnaissance Framework

Usage:
    python recon.py new <project>              Create new project
    python recon.py passive <project>          Run passive subdomain enumeration
    python recon.py resolve <project>          Resolve and filter to live hosts
    python recon.py discover <project>         Run content discovery (JS, Wayback)
    python recon.py analyze <project>          Run analysis modules
    python recon.py vulns <project>            Run vulnerability checks
    python recon.py full <project>             Run all phases
    python recon.py status <project>           Show project status
    python recon.py run <project> <module>     Run specific module
    python recon.py list                       List all projects
    python recon.py modules                    List available standalone modules

Examples:
    python recon.py new capital
    python recon.py passive capital
    python recon.py resolve capital
    python recon.py status capital
    python recon.py modules
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent / 'lib'))

from lib.core.project import ProjectManager


# ASCII Banner
BANNER = """
╦═╗┌─┐┌─┐┌─┐┌┐┌  ╔═╗┬ ┬┬┌┬┐┌─┐
╠╦╝├┤ │  │ ││││  ╚═╗│ ││ │ ├┤ 
╩╚═└─┘└─┘└─┘┘└┘  ╚═╝└─┘┴ ┴ └─┘
        Bug Bounty Recon Framework
"""


def print_banner():
    print(BANNER)


def cmd_new(args):
    """Create a new project"""
    pm = ProjectManager()
    project_path = pm.create_project(args.project)
    
    print(f"\n[OK] Project created: {project_path}")
    print(f"\nNext steps:")
    print(f"  1. Edit scope:   projects/{args.project}/scope.json")
    print(f"  2. Add domains:  projects/{args.project}/domains.txt")
    print(f"  3. Run:          python recon.py passive {args.project}")


def cmd_passive(args):
    """Run passive subdomain enumeration"""
    from lib.passive.runner import run_passive
    
    pm = ProjectManager()
    project = pm.load_project(args.project)
    
    print(f"\n[*] Running passive enumeration for: {args.project}")
    result = run_passive(project)
    
    if result['success']:
        print(f"\n[OK] Passive enumeration complete")
        print(f"    Subdomains found: {result['total']}")
        print(f"    Output: {result['output_file']}")
        print(f"\n    Next: python recon.py resolve {args.project}")
    else:
        print(f"\n[FAIL] {result.get('error', 'Unknown error')}")
        sys.exit(1)


def cmd_resolve(args):
    """Run resolution and filtering"""
    from lib.resolution.runner import run_resolution
    
    pm = ProjectManager()
    project = pm.load_project(args.project)
    
    print(f"\n[*] Running resolution for: {args.project}")
    result = run_resolution(project)
    
    if result['success']:
        print(f"\n[OK] Resolution complete")
        print(f"    Live hosts: {result['live_count']}")
        print(f"    Dead hosts: {result['dead_count']}")
        print(f"    Output: {result['live_file']}")
        print(f"\n    Next: python recon.py discover {args.project}")
    else:
        print(f"\n[FAIL] {result.get('error', 'Unknown error')}")
        sys.exit(1)


def cmd_discover(args):
    """Run content discovery"""
    from lib.discovery.runner import run_discovery
    
    pm = ProjectManager()
    project = pm.load_project(args.project)
    
    print(f"\n[*] Running discovery for: {args.project}")
    result = run_discovery(project)
    
    if result['success']:
        print(f"\n[OK] Discovery complete")
        print(f"\n    Next: python recon.py analyze {args.project}")
    else:
        print(f"\n[FAIL] {result.get('error', 'Unknown error')}")
        sys.exit(1)


def cmd_analyze(args):
    """Run analysis modules"""
    from lib.analysis.runner import run_analysis
    
    pm = ProjectManager()
    project = pm.load_project(args.project)
    
    print(f"\n[*] Running analysis for: {args.project}")
    result = run_analysis(project)
    
    if result['success']:
        print(f"\n[OK] Analysis complete")
        print(f"\n    Next: python recon.py vulns {args.project}")
    else:
        print(f"\n[FAIL] {result.get('error', 'Unknown error')}")
        sys.exit(1)


def cmd_vulns(args):
    """Run vulnerability checks"""
    from lib.vulns.runner import run_vulns
    
    pm = ProjectManager()
    project = pm.load_project(args.project)
    
    print(f"\n[*] Running vulnerability checks for: {args.project}")
    result = run_vulns(project)
    
    if result['success']:
        print(f"\n[OK] Vulnerability checks complete")
        if result.get('findings'):
            print(f"    Findings: {result['findings']}")
    else:
        print(f"\n[FAIL] {result.get('error', 'Unknown error')}")
        sys.exit(1)


def cmd_full(args):
    """Run all phases"""
    print(f"\n[*] Running full recon pipeline for: {args.project}")
    
    phases = [
        ('passive', cmd_passive),
        ('resolve', cmd_resolve),
        ('discover', cmd_discover),
        ('analyze', cmd_analyze),
        ('vulns', cmd_vulns)
    ]
    
    for phase_name, phase_func in phases:
        print(f"\n{'='*60}")
        print(f"PHASE: {phase_name.upper()}")
        print('='*60)
        try:
            phase_func(args)
        except SystemExit as e:
            if e.code != 0:
                print(f"\n[FAIL] Pipeline stopped at: {phase_name}")
                sys.exit(1)
        except Exception as e:
            print(f"\n[FAIL] Error in {phase_name}: {str(e)}")
            sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"[OK] Full pipeline complete for: {args.project}")
    print('='*60)


def cmd_status(args):
    """Show project status"""
    pm = ProjectManager()
    
    try:
        project = pm.load_project(args.project)
    except FileNotFoundError:
        print(f"\n[FAIL] Project not found: {args.project}")
        print(f"    Create with: python recon.py new {args.project}")
        sys.exit(1)
    
    print(f"\n[*] Project: {args.project}")
    print(f"    Path: {project['path']}")
    print(f"    Scope: {project['scope'].get('name', 'Unknown')}")
    print(f"    Domains: {len(project['domains'])}")
    
    phases = {
        'phase1': {'name': 'Passive', 'key_file': 'subdomains.csv'},
        'phase2': {'name': 'Resolution', 'key_file': 'live.csv'},
        'phase3': {'name': 'Discovery', 'key_file': 'endpoints.csv'},
        'phase4': {'name': 'Analysis', 'key_file': 'findings.csv'},
        'phase5': {'name': 'Vulns', 'key_file': 'takeovers.csv'}
    }
    
    print(f"\n    Phases:")
    for phase_dir, info in phases.items():
        phase_path = project['path'] / phase_dir
        key_file = phase_path / info['key_file']
        
        if key_file.exists():
            with open(key_file, 'r', encoding='utf-8') as f:
                count = sum(1 for _ in f) - 1
            mod_time = datetime.fromtimestamp(key_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            print(f"      {info['name']}: [DONE] ({count} items, {mod_time})")
        elif phase_path.exists() and any(phase_path.iterdir()):
            print(f"      {info['name']}: [PARTIAL]")
        else:
            print(f"      {info['name']}: [--]")


def cmd_run(args):
    """Run a specific module"""
    pm = ProjectManager()
    project = pm.load_project(args.project)
    
    modules = {
        # Passive tools (can run standalone)
        'google_dork': ('lib.passive.google_dork', 'run'),

        # Discovery
        'js_analyzer': ('lib.discovery.js_analyzer', 'run'),
        'wayback': ('lib.discovery.wayback', 'run'),

        # Analysis
        'reflection': ('lib.analysis.reflection', 'run'),
        'errors': ('lib.analysis.errors', 'run'),
        'auth_mapper': ('lib.analysis.auth_mapper', 'run'),
        'patterns': ('lib.analysis.patterns', 'run'),

        # Vulns
        'takeover': ('lib.vulns.takeover', 'run'),
        'misconfig': ('lib.vulns.misconfig', 'run'),
    }
    
    if args.module not in modules:
        print(f"\n[FAIL] Unknown module: {args.module}")
        print(f"    Available:")
        for name in sorted(modules.keys()):
            print(f"      - {name}")
        sys.exit(1)
    
    module_path, func_name = modules[args.module]
    
    print(f"\n[*] Running module: {args.module}")
    
    try:
        import importlib
        mod = importlib.import_module(module_path)
        func = getattr(mod, func_name)
        result = func(project)
        
        if result.get('success'):
            print(f"\n[OK] Module {args.module} complete")
        else:
            print(f"\n[FAIL] {result.get('error', 'Unknown error')}")
            sys.exit(1)
    except ImportError as e:
        print(f"\n[FAIL] Module not implemented: {args.module}")
        sys.exit(1)


def cmd_list(args):
    """List all projects"""
    pm = ProjectManager()
    projects = pm.list_projects()

    if not projects:
        print("\n[*] No projects found")
        print(f"    Create: python recon.py new <name>")
        return

    print(f"\n[*] Projects ({len(projects)}):")
    for name in projects:
        print(f"    - {name}")


def cmd_modules(args):
    """List all available standalone modules"""
    modules = {
        'passive': [
            ('google_dork', 'Run Google dork searches for sensitive files'),
        ],
        'discovery': [
            ('js_analyzer', 'Analyze JavaScript files for endpoints/secrets'),
            ('wayback', 'Fetch historical URLs from Wayback Machine'),
        ],
        'analysis': [
            ('reflection', 'Detect reflection points in responses'),
            ('errors', 'Detect error messages and stack traces'),
            ('auth_mapper', 'Map authentication endpoints'),
            ('patterns', 'Detect interesting patterns in responses'),
        ],
        'vulns': [
            ('takeover', 'Check for subdomain takeover vulnerabilities'),
            ('misconfig', 'Check for common misconfigurations'),
        ]
    }

    print(f"\n[*] Available modules for 'python recon.py run <project> <module>':\n")

    for category, mods in modules.items():
        print(f"  {category.upper()}:")
        for name, desc in mods:
            print(f"    {name:<15} - {desc}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Recon Suite - Bug Bounty Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # new
    p = subparsers.add_parser('new', help='Create new project')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_new)
    
    # passive
    p = subparsers.add_parser('passive', help='Run passive enumeration')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_passive)
    
    # resolve
    p = subparsers.add_parser('resolve', help='Resolve and filter hosts')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_resolve)
    
    # discover
    p = subparsers.add_parser('discover', help='Run content discovery')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_discover)
    
    # analyze
    p = subparsers.add_parser('analyze', help='Run analysis modules')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_analyze)
    
    # vulns
    p = subparsers.add_parser('vulns', help='Run vulnerability checks')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_vulns)
    
    # full
    p = subparsers.add_parser('full', help='Run all phases')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_full)
    
    # status
    p = subparsers.add_parser('status', help='Show project status')
    p.add_argument('project', help='Project name')
    p.set_defaults(func=cmd_status)
    
    # run
    p = subparsers.add_parser('run', help='Run specific module')
    p.add_argument('project', help='Project name')
    p.add_argument('module', help='Module name')
    p.set_defaults(func=cmd_run)
    
    # list
    p = subparsers.add_parser('list', help='List all projects')
    p.set_defaults(func=cmd_list)

    # modules
    p = subparsers.add_parser('modules', help='List available standalone modules')
    p.set_defaults(func=cmd_modules)

    args = parser.parse_args()
    
    print_banner()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
