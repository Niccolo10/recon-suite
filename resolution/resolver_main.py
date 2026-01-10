#!/usr/bin/env python3
"""
Phase 2: Resolution & Filtering - Main Orchestrator
Resolves subdomains from Phase 1, separates live/dead, groups by IP.

Usage:
    python resolver_main.py --input <phase1_results.csv> --scope <scope.json> [--config <config.json>] [--output-dir <dir>]
    
Example:
    python resolver_main.py --input ../phase1-passive/subdomains.csv --scope scope.json
"""

import argparse
import json
import sys
import csv
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scope import ScopeValidator
from core.config import ConfigManager
from resolution.httpx_runner import HttpxRunner, load_subdomains_from_csv
from resolution.ip_grouper import IPGrouper


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Phase 2: Resolve subdomains and filter to live hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input phase1-passive/subdomains.csv --scope scope.json
  %(prog)s -i subdomains.csv -s scope.json -o phase2-results/
  %(prog)s -i subdomains.csv -s scope.json --config config.json
        """
    )
    
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Path to Phase 1 subdomains CSV file'
    )
    
    parser.add_argument(
        '-s', '--scope',
        required=True,
        help='Path to scope.json file'
    )
    
    parser.add_argument(
        '-c', '--config',
        default=None,
        help='Path to config.json (optional, uses defaults if not provided)'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        default='./phase2-resolution',
        help='Output directory (default: ./phase2-resolution)'
    )
    
    parser.add_argument(
        '--subdomain-column',
        default='subdomain',
        help='CSV column name containing subdomains (default: subdomain)'
    )
    
    parser.add_argument(
        '--skip-scope-filter',
        action='store_true',
        help='Skip scope filtering (process all subdomains)'
    )
    
    return parser.parse_args()


def run_resolution(
    input_file: str,
    scope_file: str,
    config_file: str = None,
    output_dir: str = './phase2-resolution',
    subdomain_column: str = 'subdomain',
    skip_scope_filter: bool = False
) -> dict:
    """
    Run Phase 2 resolution pipeline.
    
    Args:
        input_file: Path to Phase 1 subdomains CSV
        scope_file: Path to scope.json
        config_file: Path to config.json (optional)
        output_dir: Output directory
        subdomain_column: CSV column name for subdomains
        skip_scope_filter: Skip scope validation
        
    Returns:
        Dict with paths to output files and statistics
    """
    start_time = datetime.now()
    
    print("\n" + "=" * 60)
    print("PHASE 2: RESOLUTION & FILTERING")
    print("=" * 60)
    
    # Setup output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load configuration
    config = ConfigManager(config_file)
    phase2_config = config.get_phase2_config()
    httpx_config = phase2_config.get('httpx', {})
    
    # Load scope
    print("\n[STEP 1] Loading scope configuration...")
    scope = ScopeValidator(scope_file)
    
    # Load subdomains from Phase 1
    print("\n[STEP 2] Loading subdomains from Phase 1...")
    input_path = Path(input_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    
    all_subdomains = load_subdomains_from_csv(input_file, subdomain_column)
    print(f"[INFO] Loaded {len(all_subdomains)} subdomains from {input_file}")
    
    if not all_subdomains:
        print("[WARNING] No subdomains loaded. Check input file and column name.")
        return {'error': 'No subdomains loaded'}
    
    # Filter by scope
    print("\n[STEP 3] Filtering by scope...")
    if skip_scope_filter:
        print("[INFO] Scope filtering skipped (--skip-scope-filter)")
        in_scope_subdomains = all_subdomains
        out_of_scope = []
    else:
        in_scope_subdomains, out_of_scope = scope.validate_and_report(all_subdomains)
    
    if not in_scope_subdomains:
        print("[WARNING] No in-scope subdomains to process.")
        return {'error': 'No in-scope subdomains'}
    
    # Save out-of-scope for reference
    if out_of_scope:
        oos_file = output_path / 'out_of_scope.txt'
        with open(oos_file, 'w', encoding='utf-8') as f:
            for subdomain in out_of_scope:
                f.write(f"{subdomain}\n")
        print(f"[INFO] Out-of-scope subdomains saved: {oos_file}")
    
    # Run httpx
    print("\n[STEP 4] Running httpx resolution...")
    httpx_runner = HttpxRunner(httpx_config)
    live_file, dead_file = httpx_runner.run(in_scope_subdomains, str(output_path))
    
    # Group by IP
    print("\n[STEP 5] Grouping by IP...")
    ip_grouper = IPGrouper()
    ip_groups_file = ip_grouper.process(live_file, str(output_path / 'ip_groups.csv'))
    
    # Calculate statistics
    live_count = 0
    dead_count = 0
    
    if live_file:
        with open(live_file, 'r', encoding='utf-8') as f:
            live_count = sum(1 for _ in f) - 1  # Subtract header
    
    if dead_file:
        with open(dead_file, 'r', encoding='utf-8') as f:
            dead_count = sum(1 for _ in f) - 1  # Subtract header
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Save metadata
    metadata = {
        'phase': 'resolution',
        'timestamp': datetime.now().isoformat(),
        'elapsed_seconds': round(elapsed, 2),
        'input_file': str(input_path.absolute()),
        'scope_file': str(Path(scope_file).absolute()),
        'config': httpx_config,
        'statistics': {
            'total_input': len(all_subdomains),
            'in_scope': len(in_scope_subdomains),
            'out_of_scope': len(out_of_scope),
            'live_hosts': live_count,
            'dead_hosts': dead_count,
            'unique_ips': len(ip_grouper.get_groups())
        },
        'outputs': {
            'live_hosts': str(live_file),
            'dead_hosts': str(dead_file),
            'ip_groups': ip_groups_file
        }
    }
    
    metadata_file = output_path / 'metadata.json'
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 60)
    print("PHASE 2 COMPLETE")
    print("=" * 60)
    print(f"\nStatistics:")
    print(f"  Input subdomains: {len(all_subdomains)}")
    print(f"  In-scope: {len(in_scope_subdomains)}")
    print(f"  Out-of-scope: {len(out_of_scope)}")
    print(f"  Live hosts: {live_count}")
    print(f"  Dead hosts: {dead_count}")
    print(f"  Unique IPs: {len(ip_grouper.get_groups())}")
    print(f"  Time elapsed: {elapsed:.1f}s")
    
    print(f"\nOutputs:")
    print(f"  Live hosts: {live_file}")
    print(f"  Dead hosts: {dead_file}")
    print(f"  IP groups: {ip_groups_file}")
    print(f"  Metadata: {metadata_file}")
    
    return {
        'success': True,
        'live_hosts_file': live_file,
        'dead_hosts_file': dead_file,
        'ip_groups_file': ip_groups_file,
        'metadata_file': str(metadata_file),
        'statistics': metadata['statistics']
    }


def main():
    """Main entry point"""
    args = parse_args()
    
    try:
        result = run_resolution(
            input_file=args.input,
            scope_file=args.scope,
            config_file=args.config,
            output_dir=args.output_dir,
            subdomain_column=args.subdomain_column,
            skip_scope_filter=args.skip_scope_filter
        )
        
        if result.get('error'):
            print(f"\n[ERROR] {result['error']}")
            sys.exit(1)
        
        print("\n[SUCCESS] Phase 2 completed successfully")
        print("\nNext steps:")
        print(f"  1. Review live hosts: {result['live_hosts_file']}")
        print(f"  2. Check IP groups for shared infrastructure: {result['ip_groups_file']}")
        print(f"  3. Run Phase 3 discovery on live hosts")
        print(f"  4. Check dead hosts for takeover vulnerabilities: {result['dead_hosts_file']}")
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
