"""
Scope Validator
"""

import re
from typing import List, Tuple, Dict


class ScopeValidator:
    """Validates domains against scope rules"""
    
    def __init__(self, scope: Dict):
        self.in_scope_patterns = scope.get('in_scope', [])
        self.out_of_scope_patterns = scope.get('out_of_scope', [])
        self.name = scope.get('name', 'Unknown')
        
        self._in_compiled = [self._compile(p) for p in self.in_scope_patterns]
        self._out_compiled = [self._compile(p) for p in self.out_of_scope_patterns]
    
    def _compile(self, pattern: str) -> re.Pattern:
        # Handle .domain.com format (means domain.com and all subdomains)
        if pattern.startswith('.'):
            # .example.com -> matches example.com and *.example.com
            base_domain = pattern[1:]  # Remove leading dot
            escaped = re.escape(base_domain)
            # Match apex domain OR any subdomain
            regex = f'(([a-zA-Z0-9-]+\\.)*)?{escaped}'
        else:
            escaped = re.escape(pattern)
            regex = escaped.replace(r'\*\.', r'([a-zA-Z0-9-]+\.)*')
            regex = regex.replace(r'\*', r'[a-zA-Z0-9-]*')
        return re.compile(f'^{regex}$', re.IGNORECASE)
    
    def is_in_scope(self, domain: str) -> bool:
        domain = self._normalize(domain)
        
        for pattern in self._out_compiled:
            if pattern.match(domain):
                return False
        
        for pattern in self._in_compiled:
            if pattern.match(domain):
                return True
        
        return False
    
    def _normalize(self, domain: str) -> str:
        domain = domain.lower().strip()
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        if ':' in domain:
            domain = domain.split(':')[0]
        if '/' in domain:
            domain = domain.split('/')[0]
        return domain
    
    def filter(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        in_scope = []
        out_of_scope = []
        for domain in domains:
            if self.is_in_scope(domain):
                in_scope.append(domain)
            else:
                out_of_scope.append(domain)
        return in_scope, out_of_scope
    
    def filter_and_report(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        in_scope, out_of_scope = self.filter(domains)
        print(f"[SCOPE] {self.name}")
        print(f"  Total: {len(domains)}")
        print(f"  In-scope: {len(in_scope)}")
        print(f"  Out-of-scope: {len(out_of_scope)}")
        if out_of_scope and len(out_of_scope) <= 10:
            print(f"  Excluded: {', '.join(out_of_scope)}")
        elif out_of_scope:
            print(f"  Excluded (first 10): {', '.join(out_of_scope[:10])}...")
        return in_scope, out_of_scope
