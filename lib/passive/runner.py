"""
Passive Enumeration Runner
Orchestrates all passive subdomain enumeration tools.
"""

import csv
import json
import sys
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .crtsh import CrtshTool
from .sublist3r_tool import Sublist3rTool
from .alienvault_otx import AlienVaultOTXTool

# Global stop event for graceful shutdown
_stop_event = threading.Event()


def is_stopped() -> bool:
    """Check if stop was requested"""
    return _stop_event.is_set()


def request_stop():
    """Request graceful stop"""
    _stop_event.set()


def _keyboard_listener():
    """Listen for 'q' keypress to quit"""
    try:
        if sys.platform == 'win32':
            import msvcrt
            while not _stop_event.is_set():
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in (b'q', b'Q'):
                        print("\n[!] Quit requested - stopping gracefully...")
                        _stop_event.set()
                        break
                _stop_event.wait(0.1)  # Check every 100ms
        else:
            # Unix/Linux/Mac
            import select
            import tty
            import termios
            old_settings = termios.tcgetattr(sys.stdin)
            try:
                tty.setcbreak(sys.stdin.fileno())
                while not _stop_event.is_set():
                    if select.select([sys.stdin], [], [], 0.1)[0]:
                        key = sys.stdin.read(1)
                        if key in ('q', 'Q'):
                            print("\n[!] Quit requested - stopping gracefully...")
                            _stop_event.set()
                            break
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    except Exception:
        pass  # Silently fail if keyboard listener can't start


def normalize_domain(domain: str) -> str:
    """Strip wildcard prefix from domain for API queries"""
    d = domain.strip().lower()
    if d.startswith('*.'):
        d = d[2:]
    return d


def run_passive(project: Dict) -> Dict:
    """
    Run passive subdomain enumeration.

    Args:
        project: Project configuration dict

    Returns:
        Result dict with success status and output info
    """
    raw_domains = project['domains']
    config = project['config']
    output_dir = project['phases']['phase1']

    if not raw_domains:
        return {'success': False, 'error': 'No domains in domains.txt'}

    # Normalize domains - strip wildcard prefix for API queries
    domains = list(set(normalize_domain(d) for d in raw_domains))
    
    print(f"\n[PASSIVE] Starting enumeration for {len(domains)} domain(s)")
    print(f"[PASSIVE] Domains: {', '.join(domains)}")
    
    # Initialize enabled tools
    tools = []
    passive_config = config.get('passive', {})
    
    # crt.sh
    if passive_config.get('crtsh', {}).get('enabled', True):
        tools.append(('crtsh', CrtshTool(passive_config.get('crtsh', {}))))
    
    # Sublist3r
    if passive_config.get('sublist3r', {}).get('enabled', True):
        tools.append(('sublist3r', Sublist3rTool(passive_config.get('sublist3r', {}))))
    
    # Microsoft TI (if configured with tokens)
    ms_config = passive_config.get('microsoft_ti', {})
    if ms_config.get('enabled', False) and ms_config.get('processes_input'):
        try:
            from .microsoft_ti import MicrosoftTITool
            tools.append(('microsoft_ti', MicrosoftTITool(ms_config)))
        except ValueError as e:
            print(f"[PASSIVE] Microsoft TI: {e}")
    
    # SecurityTrails (if configured with cookies)
    st_config = passive_config.get('securitytrails', {})
    if st_config.get('enabled', False) and st_config.get('sec_id') and st_config.get('processes_input'):
        try:
            from .securitytrails import SecurityTrailsTool
            tools.append(('securitytrails', SecurityTrailsTool(st_config)))
        except ValueError as e:
            print(f"[PASSIVE] SecurityTrails: {e}")

    # Google Dork (if configured with API keys)
    gd_config = passive_config.get('google_dork', {})
    if gd_config.get('enabled', False) and gd_config.get('api_keys') and gd_config.get('cx'):
        try:
            from .google_dork import GoogleDorkTool
            gd_tool = GoogleDorkTool(gd_config)
            gd_tool._output_dir = output_dir  # Store output dir for report generation
            tools.append(('google_dork', gd_tool))
        except ValueError as e:
            print(f"[PASSIVE] Google Dork: {e}")

    # AlienVault OTX (enabled by default, optional API key)
    otx_config = passive_config.get('alienvault_otx', {})
    if otx_config.get('enabled', True):
        try:
            tools.append(('alienvault_otx', AlienVaultOTXTool(otx_config)))
        except ValueError as e:
            print(f"[PASSIVE] AlienVault OTX: {e}")

    if not tools:
        return {'success': False, 'error': 'No tools enabled'}

    print(f"[PASSIVE] Tools: {', '.join(name for name, _ in tools)}")
    print(f"[PASSIVE] Press 'q' to quit at any time")

    # Reset and start keyboard listener
    _stop_event.clear()
    kb_thread = threading.Thread(target=_keyboard_listener, daemon=True)
    kb_thread.start()

    # Check if parallel execution is enabled
    parallel_enabled = passive_config.get('parallel_tools', False)

    # Run each tool
    all_results = {}
    was_stopped = False

    try:
        if parallel_enabled and len(tools) > 1:
            print(f"[PASSIVE] Running {len(tools)} tools in PARALLEL...")

            def run_tool(tool_tuple):
                tool_name, tool = tool_tuple
                try:
                    if is_stopped():
                        return tool_name, [], "Stopped by user"
                    results = tool.run(domains)
                    return tool_name, results, None
                except Exception as e:
                    return tool_name, [], str(e)

            with ThreadPoolExecutor(max_workers=len(tools)) as executor:
                futures = {executor.submit(run_tool, t): t[0] for t in tools}
                for future in as_completed(futures):
                    if is_stopped():
                        was_stopped = True
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    tool_name, results, error = future.result()
                    if error:
                        print(f"[PASSIVE] {tool_name} failed: {error}")
                    else:
                        print(f"[PASSIVE] {tool_name}: {len(results)} subdomains")
                    all_results[tool_name] = results
        else:
            if len(tools) > 1:
                print(f"[PASSIVE] Running tools sequentially (set parallel_tools: true in config for parallel)")
            for tool_name, tool in tools:
                if is_stopped():
                    was_stopped = True
                    break
                print(f"\n[PASSIVE] Running {tool_name}...")
                try:
                    results = tool.run(domains)
                    all_results[tool_name] = results
                    print(f"[PASSIVE] {tool_name}: {len(results)} subdomains")
                except Exception as e:
                    print(f"[PASSIVE] {tool_name} failed: {str(e)}")
                    all_results[tool_name] = []
    finally:
        # Stop keyboard listener
        _stop_event.set()

    if was_stopped:
        print(f"\n[!] Execution stopped by user")
    
    # Deduplicate
    print(f"\n[PASSIVE] Deduplicating...")
    merged = deduplicate(all_results)
    print(f"[PASSIVE] Unique: {len(merged)}")
    
    # Save output
    output_file = output_dir / 'subdomains.csv'
    save_results(merged, output_file, domains)
    
    # Save individual tool outputs
    temp_dir = output_dir / 'raw'
    temp_dir.mkdir(exist_ok=True)
    
    for tool_name, results in all_results.items():
        tool_file = temp_dir / f'{tool_name}.json'
        out_list = []
        for item in results:
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[1], dict):
                s, m = item
            else:
                s, m = item, {}
            out_list.append({'subdomain': s, 'metadata': m})

        with open(tool_file, 'w', encoding='utf-8') as f:
            json.dump(out_list, f, indent=2)
    
    # Save metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'domains': domains,
        'tools': {name: len(results) for name, results in all_results.items()},
        'total_unique': len(merged)
    }
    
    with open(output_dir / 'metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    
    return {
        'success': True,
        'total': len(merged),
        'output_file': str(output_file)
    }


def deduplicate(tool_results: Dict[str, List]) -> Dict[str, Dict]:
    """Deduplicate results from multiple tools with confidence scoring.

    Accepts tool result items in either of these forms:
    - `(subdomain, metadata_dict)`
    - `subdomain` (string)
    """
    merged = {}

    for tool_name, results in tool_results.items():
        for item in results:
            if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[1], dict):
                subdomain, metadata = item
            else:
                subdomain, metadata = item, {}

            key = subdomain.lower().strip()

            if key not in merged:
                merged[key] = {
                    'original': subdomain,
                    'sources': [tool_name],
                    'metadata': {tool_name: metadata},
                    'first_seen': datetime.now().isoformat(),
                    'is_wildcard': subdomain.startswith('*.')
                }
            else:
                if tool_name not in merged[key]['sources']:
                    merged[key]['sources'].append(tool_name)
                merged[key]['metadata'][tool_name] = metadata
    
    # Calculate confidence
    for key, data in merged.items():
        num_sources = len(data['sources'])
        if num_sources >= 3:
            data['confidence'] = 'HIGH'
        elif num_sources == 2:
            data['confidence'] = 'MEDIUM'
        else:
            data['confidence'] = 'LOW'
    
    return merged


def save_results(merged: Dict[str, Dict], output_file: Path, input_domains: List[str]):
    """Save deduplicated results to CSV"""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    rows = []
    for subdomain_key, data in merged.items():
        apex = find_apex(data['original'], input_domains)
        
        # Merge metadata from all sources
        all_metadata = {}
        for source, meta in data['metadata'].items():
            for k, v in meta.items():
                if k not in all_metadata and v:
                    all_metadata[k] = v
        
        rows.append({
            'subdomain': data['original'],
            'apex_domain': apex,
            'sources': ';'.join(data['sources']),
            'confidence': data['confidence'],
            'is_wildcard': data['is_wildcard'],
            'host_provider': all_metadata.get('host_provider', ''),
            'mail_provider': all_metadata.get('mail_provider', ''),
            'tags': all_metadata.get('tags', ''),
            'first_seen': data['first_seen']
        })
    
    # Sort by confidence then alphabetically
    confidence_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    rows.sort(key=lambda x: (confidence_order[x['confidence']], x['subdomain']))
    
    # Write CSV
    fieldnames = ['subdomain', 'apex_domain', 'sources', 'confidence', 'is_wildcard',
                  'host_provider', 'mail_provider', 'tags', 'first_seen']
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[PASSIVE] Saved: {output_file}")


def find_apex(subdomain: str, input_domains: List[str]) -> str:
    """Find which input domain this subdomain belongs to"""
    subdomain_clean = subdomain.lower().replace('*.', '')
    
    for domain in input_domains:
        domain_lower = domain.lower()
        if subdomain_clean == domain_lower or subdomain_clean.endswith('.' + domain_lower):
            return domain
    
    parts = subdomain_clean.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    
    return subdomain
