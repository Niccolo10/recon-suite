"""
Results merger - creates final unified output CSV
"""

import csv
import json
from pathlib import Path
from typing import Dict, List


class ResultsMerger:
    """Merges deduplicated results into final output format"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.final_output = config['final_results']
    
    def create_final_output(self, subdomains: Dict[str, Dict], input_domains: List[str]) -> str:
        """
        Create final CSV output file
        
        Args:
            subdomains: Deduplicated subdomain data
            input_domains: Original input domains for apex extraction
            
        Returns:
            Path to final output file
        """
        output_path = Path(self.final_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare data for CSV
        csv_data = self._prepare_csv_data(subdomains, input_domains)
        
        # Sort by confidence (HIGH -> MEDIUM -> LOW), then alphabetically
        confidence_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        csv_data.sort(key=lambda x: (confidence_order[x['confidence_score']], x['subdomain']))
        
        # Write CSV
        self._write_csv(csv_data, output_path)
        
        return str(output_path)
    
    def _prepare_csv_data(self, subdomains: Dict[str, Dict], input_domains: List[str]) -> List[Dict]:
        """Prepare data for CSV export"""
        csv_rows = []
        
        for subdomain, data in subdomains.items():
            # Determine apex domain
            apex_domain = self._find_apex_domain(data['original'], input_domains)
            
            # Merge metadata from all sources
            merged_metadata = self._merge_metadata(data['metadata'])
            
            # Extract common fields
            host_provider = merged_metadata.get('host_provider', '')
            mail_provider = merged_metadata.get('mail_provider', '')
            tags = merged_metadata.get('tags', '')
            
            # Prepare additional info (all metadata as JSON)
            additional_info = {
                k: v for k, v in merged_metadata.items()
                if k not in ['host_provider', 'mail_provider', 'tags', 'source']
            }
            
            # Add wildcard flag if needed
            if data['is_wildcard']:
                additional_info['wildcard'] = True
            
            row = {
                'subdomain': data['original'],
                'apex_domain': apex_domain,
                'ip': '',  # To be filled by active enumeration later
                'source_tools': ';'.join(data['sources']),
                'confidence_score': data['confidence'],
                'first_discovered': data['first_seen'],
                'host_provider': host_provider,
                'mail_provider': mail_provider,
                'tags': tags,
                'additional_info': json.dumps(additional_info) if additional_info else ''
            }
            
            csv_rows.append(row)
        
        return csv_rows
    
    def _find_apex_domain(self, subdomain: str, input_domains: List[str]) -> str:
        """Find which input domain this subdomain belongs to"""
        subdomain_clean = subdomain.lower().replace('*.', '')
        
        for domain in input_domains:
            domain_lower = domain.lower()
            if subdomain_clean == domain_lower or subdomain_clean.endswith('.' + domain_lower):
                return domain
        
        # Fallback: extract last 2 parts
        parts = subdomain_clean.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        return subdomain
    
    def _merge_metadata(self, metadata_by_source: Dict[str, Dict]) -> Dict:
        """
        Merge metadata from multiple sources
        Prioritizes non-empty values
        """
        merged = {}
        
        for source, meta in metadata_by_source.items():
            for key, value in meta.items():
                # Skip if already have a non-empty value for this key
                if key in merged and merged[key]:
                    continue
                
                # Add value if non-empty
                if value:
                    merged[key] = value
        
        return merged
    
    def _write_csv(self, data: List[Dict], output_path: Path):
        """Write data to CSV file"""
        if not data:
            print(f"[MERGER] No data to write")
            return
        
        # Define column order
        fieldnames = [
            'subdomain',
            'apex_domain',
            'ip',
            'source_tools',
            'confidence_score',
            'first_discovered',
            'host_provider',
            'mail_provider',
            'tags',
            'additional_info'
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        print(f"[MERGER] Wrote {len(data)} rows to {output_path}")