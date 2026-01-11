"""
Passive Enumeration Runner
Orchestrates all passive subdomain enumeration tools.
"""

import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

from .crtsh import CrtshTool
from .sublist3r_tool import Sublist3rTool


def run_passive(project: Dict) -> Dict:
    """
    Run passive subdomain enumeration.
    
    Args:
        project: Project configuration dict
        
    Returns:
        Result dict with success status and output info
    """
    domains = project['domains']
    config = project['config']
    output_dir = project['phases']['phase1']
    
    if not domains:
        return {'success': False, 'error': 'No domains in domains.txt'}
    
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
    
    if not tools:
        return {'success': False, 'error': 'No tools enabled'}
    
    print(f"[PASSIVE] Tools: {', '.join(name for name, _ in tools)}")
    
    # Run each tool
    all_results = {}
    
    for tool_name, tool in tools:
        print(f"\n[PASSIVE] Running {tool_name}...")
        try:
            results = tool.run(domains)
            all_results[tool_name] = results
            print(f"[PASSIVE] {tool_name}: {len(results)} subdomains")
        except Exception as e:
            print(f"[PASSIVE] {tool_name} failed: {str(e)}")
            all_results[tool_name] = []
    
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
        with open(tool_file, 'w', encoding='utf-8') as f:
            json.dump([{'subdomain': s, 'metadata': m} for s, m in results], f, indent=2)
    
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


def deduplicate(tool_results: Dict[str, List[Tuple[str, Dict]]]) -> Dict[str, Dict]:
    """Deduplicate results from multiple tools with confidence scoring"""
    merged = {}
    
    for tool_name, results in tool_results.items():
        for subdomain, metadata in results:
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
