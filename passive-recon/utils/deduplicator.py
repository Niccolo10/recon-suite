"""
Smart deduplication engine for subdomain enumeration results
Merges results from multiple tools and tracks sources
"""

from typing import Dict, List, Tuple, Set
from collections import defaultdict
from datetime import datetime


class Deduplicator:
    """Handles deduplication and merging of subdomain results"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.case_sensitive = config.get('case_sensitive', False)
        self.remove_wildcards = config.get('remove_wildcards', False)
        self.flag_wildcards = config.get('flag_wildcards', True)
        
        # Storage for deduplicated results
        self.subdomains = {}  # key: normalized subdomain, value: metadata
    
    def process(self, tool_results: Dict[str, List[Tuple[str, Dict]]]) -> Dict[str, Dict]:
        """
        Process results from multiple tools and deduplicate
        
        Args:
            tool_results: Dict mapping tool_name -> [(subdomain, metadata), ...]
            
        Returns:
            Dict mapping subdomain -> {sources: [], metadata: {}, confidence: str}
        """
        print(f"\n[DEDUP] Starting deduplication process...")
        
        # Process each tool's results
        for tool_name, results in tool_results.items():
            print(f"[DEDUP] Processing {len(results)} results from {tool_name}")
            
            for subdomain, metadata in results:
                self._add_subdomain(subdomain, tool_name, metadata)
        
        # Calculate confidence scores
        self._calculate_confidence()
        
        # Apply wildcard filtering if configured
        if self.remove_wildcards:
            self._remove_wildcards()
        
        print(f"[DEDUP] Deduplication complete. {len(self.subdomains)} unique subdomains")
        
        return self.subdomains
    
    def _normalize_key(self, subdomain: str) -> str:
        """Normalize subdomain for deduplication key"""
        if not self.case_sensitive:
            subdomain = subdomain.lower()
        
        return subdomain.strip()
    
    def _add_subdomain(self, subdomain: str, source: str, metadata: Dict):
        """Add a subdomain to the deduplicated set"""
        key = self._normalize_key(subdomain)
        
        # Check for wildcards
        is_wildcard = subdomain.startswith('*.')
        
        if key not in self.subdomains:
            # New subdomain
            self.subdomains[key] = {
                'original': subdomain,  # Keep original casing
                'sources': [source],
                'first_seen': datetime.now().isoformat(),
                'metadata': {source: metadata},
                'is_wildcard': is_wildcard,
                'confidence': 'LOW'  # Will be calculated later
            }
        else:
            # Subdomain already exists - merge data
            if source not in self.subdomains[key]['sources']:
                self.subdomains[key]['sources'].append(source)
            
            # Merge metadata from this source
            self.subdomains[key]['metadata'][source] = metadata
    
    def _calculate_confidence(self):
        """Calculate confidence scores based on number of sources"""
        for subdomain, data in self.subdomains.items():
            num_sources = len(data['sources'])
            
            if num_sources >= 3:
                data['confidence'] = 'HIGH'
            elif num_sources == 2:
                data['confidence'] = 'MEDIUM'
            else:
                data['confidence'] = 'LOW'
    
    def _remove_wildcards(self):
        """Remove wildcard entries if configured"""
        wildcards_removed = 0
        
        to_remove = [
            key for key, data in self.subdomains.items()
            if data['is_wildcard']
        ]
        
        for key in to_remove:
            del self.subdomains[key]
            wildcards_removed += 1
        
        if wildcards_removed > 0:
            print(f"[DEDUP] Removed {wildcards_removed} wildcard entries")
    
    def get_statistics(self) -> Dict:
        """Get deduplication statistics"""
        total = len(self.subdomains)
        
        confidence_counts = {
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        wildcard_count = 0
        
        for data in self.subdomains.values():
            confidence_counts[data['confidence']] += 1
            if data['is_wildcard']:
                wildcard_count += 1
        
        return {
            'total_unique': total,
            'confidence_breakdown': confidence_counts,
            'wildcards': wildcard_count,
            'non_wildcards': total - wildcard_count
        }