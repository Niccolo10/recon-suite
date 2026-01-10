"""
Domain validation and normalization utilities
"""

import re
from typing import Optional


class DomainValidator:
    """Validates and normalizes domain names"""
    
    # Basic domain regex pattern
    DOMAIN_PATTERN = re.compile(
        r'^(\*\.)?'  # Optional wildcard
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'  # Subdomains
        r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'  # Domain
        r'(\.[a-zA-Z]{2,})+$'  # TLD
    )
    
    def __init__(self):
        pass
    
    def normalize(self, domain: str) -> str:
        """
        Normalize a domain name
        
        Args:
            domain: Raw domain string
            
        Returns:
            Normalized domain (lowercase, trimmed, no trailing dot)
        """
        if not domain:
            return ""
        
        # Convert to lowercase
        domain = domain.lower()
        
        # Strip whitespace
        domain = domain.strip()
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Remove http:// or https:// if present
        domain = re.sub(r'^https?://', '', domain)
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        # Extract just the domain if there's a path
        if '/' in domain:
            domain = domain.split('/')[0]
        
        return domain
    
    def is_valid_domain(self, domain: str) -> bool:
        """
        Check if a domain is valid
        
        Args:
            domain: Domain to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain:
            return False
        
        # Check length
        if len(domain) > 253:
            return False
        
        # Check pattern
        if not self.DOMAIN_PATTERN.match(domain):
            return False
        
        # Check each label length
        labels = domain.replace('*.', '').split('.')
        for label in labels:
            if len(label) > 63 or len(label) == 0:
                return False
        
        return True
    
    def is_wildcard(self, domain: str) -> bool:
        """Check if domain is a wildcard"""
        return domain.startswith('*.')
    
    def extract_apex_domain(self, subdomain: str) -> str:
        """
        Extract apex domain from a subdomain
        
        Args:
            subdomain: Full subdomain (e.g., api.example.com)
            
        Returns:
            Apex domain (e.g., example.com)
        """
        # Remove wildcard if present
        clean = subdomain.replace('*.', '')
        
        # Split by dots
        parts = clean.split('.')
        
        # Apex is typically last 2 parts, but could be more for ccTLDs
        # This is a simple heuristic
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        return clean
    
    def is_subdomain_of(self, subdomain: str, apex: str) -> bool:
        """
        Check if subdomain belongs to apex domain
        
        Args:
            subdomain: Subdomain to check
            apex: Apex domain
            
        Returns:
            True if subdomain is under apex domain
        """
        subdomain = self.normalize(subdomain).replace('*.', '')
        apex = self.normalize(apex)
        
        return subdomain == apex or subdomain.endswith('.' + apex)