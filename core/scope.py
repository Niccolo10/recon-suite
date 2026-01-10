"""
Scope Validator
Enforces in-scope and out-of-scope rules across all phases.
Supports wildcard patterns (*.target.com) and exact matches.
"""

import json
import re
import fnmatch
from pathlib import Path
from typing import List, Tuple, Dict, Optional


class ScopeValidator:
    """
    Validates domains/subdomains against defined scope rules.
    Used by all phases to ensure we only process in-scope targets.
    """
    
    def __init__(self, scope_file: str):
        """
        Initialize with scope configuration file.
        
        Args:
            scope_file: Path to scope.json
        """
        self.scope_file = Path(scope_file)
        self.scope_data = self._load_scope()
        
        self.in_scope_patterns = self.scope_data.get('in_scope', [])
        self.out_of_scope_patterns = self.scope_data.get('out_of_scope', [])
        self.name = self.scope_data.get('name', 'Unknown Program')
        
        # Compile patterns for efficiency
        self._in_scope_compiled = [self._compile_pattern(p) for p in self.in_scope_patterns]
        self._out_of_scope_compiled = [self._compile_pattern(p) for p in self.out_of_scope_patterns]
        
        print(f"[SCOPE] Loaded scope: {self.name}")
        print(f"[SCOPE] In-scope patterns: {len(self.in_scope_patterns)}")
        print(f"[SCOPE] Out-of-scope patterns: {len(self.out_of_scope_patterns)}")
    
    def _load_scope(self) -> Dict:
        """Load scope configuration from JSON file"""
        if not self.scope_file.exists():
            raise FileNotFoundError(f"Scope file not found: {self.scope_file}")
        
        # Try different encodings (handles Windows BOM issues)
        encodings = ['utf-8-sig', 'utf-8', 'utf-16', 'latin-1']
        
        for encoding in encodings:
            try:
                with open(self.scope_file, 'r', encoding=encoding) as f:
                    return json.load(f)
            except (UnicodeDecodeError, UnicodeError):
                continue
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in scope file: {e}")
        
        raise ValueError(f"Could not decode scope file with any supported encoding")
    
    def _compile_pattern(self, pattern: str) -> re.Pattern:
        """
        Convert wildcard pattern to regex.
        
        Supports:
        - *.target.com -> matches any subdomain of target.com
        - target.com -> exact match
        - specific.other.com -> exact match
        """
        # Escape special regex characters except *
        escaped = re.escape(pattern)
        
        # Convert wildcard * to regex pattern
        # \*\. at start means "any subdomain" -> ([a-zA-Z0-9-]+\.)*
        regex_pattern = escaped.replace(r'\*\.', r'([a-zA-Z0-9-]+\.)*')
        
        # Also handle * anywhere (though less common)
        regex_pattern = regex_pattern.replace(r'\*', r'[a-zA-Z0-9-]*')
        
        # Anchor to full string match
        regex_pattern = f'^{regex_pattern}$'
        
        return re.compile(regex_pattern, re.IGNORECASE)
    
    def is_in_scope(self, domain: str) -> bool:
        """
        Check if domain is in scope.
        
        Logic:
        1. Must match at least one in_scope pattern
        2. Must NOT match any out_of_scope pattern
        
        Args:
            domain: Domain or subdomain to check
            
        Returns:
            True if in scope, False otherwise
        """
        domain = domain.lower().strip()
        
        # Remove protocol if present
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Check out_of_scope first (exclusions take priority)
        for pattern in self._out_of_scope_compiled:
            if pattern.match(domain):
                return False
        
        # Check in_scope
        for pattern in self._in_scope_compiled:
            if pattern.match(domain):
                return True
        
        return False
    
    def filter_domains(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        Filter a list of domains by scope.
        
        Args:
            domains: List of domains to filter
            
        Returns:
            Tuple of (in_scope_domains, out_of_scope_domains)
        """
        in_scope = []
        out_of_scope = []
        
        for domain in domains:
            if self.is_in_scope(domain):
                in_scope.append(domain)
            else:
                out_of_scope.append(domain)
        
        return in_scope, out_of_scope
    
    def validate_and_report(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        Filter domains and print summary.
        
        Args:
            domains: List of domains to filter
            
        Returns:
            Tuple of (in_scope_domains, out_of_scope_domains)
        """
        in_scope, out_of_scope = self.filter_domains(domains)
        
        print(f"\n[SCOPE] Validation Results:")
        print(f"  Total: {len(domains)}")
        print(f"  In-scope: {len(in_scope)}")
        print(f"  Out-of-scope: {len(out_of_scope)}")
        
        if out_of_scope and len(out_of_scope) <= 10:
            print(f"  Excluded: {', '.join(out_of_scope)}")
        elif out_of_scope:
            print(f"  Excluded (first 10): {', '.join(out_of_scope[:10])}...")
        
        return in_scope, out_of_scope
    
    def get_scope_summary(self) -> Dict:
        """Get scope configuration summary"""
        return {
            'name': self.name,
            'in_scope_patterns': self.in_scope_patterns,
            'out_of_scope_patterns': self.out_of_scope_patterns
        }


def create_scope_template(output_path: str, program_name: str = "Target Program"):
    """
    Create a template scope.json file.
    
    Args:
        output_path: Where to save the template
        program_name: Name of the bug bounty program
    """
    template = {
        "name": program_name,
        "in_scope": [
            "*.target.com",
            "*.target.io"
        ],
        "out_of_scope": [
            "support.target.com",
            "status.target.com",
            "*.cdn.target.com"
        ],
        "notes": "Add any notes about scope here"
    }
    
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(template, f, indent=2)
    
    print(f"[SCOPE] Template created: {output_path}")
    return output_path


# Quick test when run directly
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "create-template":
        output = sys.argv[2] if len(sys.argv) > 2 else "./scope.json"
        create_scope_template(output)
    else:
        print("Usage:")
        print("  python scope.py create-template [output_path]")
        print("")
        print("Example scope.json:")
        print(json.dumps({
            "name": "Example Program",
            "in_scope": ["*.example.com"],
            "out_of_scope": ["status.example.com"]
        }, indent=2))
