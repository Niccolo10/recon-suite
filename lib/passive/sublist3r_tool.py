"""
Sublist3r tool wrapper
Uses subprocess to run sublist3r module
"""

import sys
import os
import subprocess
import re
from pathlib import Path
from typing import List, Tuple, Dict
import tempfile

from .base_tool import BaseTool

try:
    import sublist3r
    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False


class Sublist3rTool(BaseTool):
    """Sublist3r subdomain enumeration wrapper"""
    
    def __init__(self, config: Dict = None):
        config = config or {}
        super().__init__(config)
        self.name = "sublist3r"
        self.threads = config.get('threads', 40)
        self.engines = config.get('engines', None)
        self.enable_bruteforce = config.get('enable_bruteforce', False)
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """Run Sublist3r on domains using subprocess"""
        if not SUBLIST3R_AVAILABLE:
            print(f"  [{self.name}] Not installed, skipping")
            return []
        
        all_results = []
        
        for domain in domains:
            print(f"  [{self.name}] Enumerating {domain}...")
            
            try:
                subdomains = self._enumerate(domain)
                print(f"  [{self.name}] Found {len(subdomains)} for {domain}")
                
                for subdomain in subdomains:
                    metadata = {
                        'source': 'sublist3r',
                        'parent_domain': domain
                    }
                    all_results.append((subdomain.lower(), metadata))
                    
            except Exception as e:
                print(f"  [{self.name}] Error for {domain}: {str(e)}")
                continue
        
        return all_results
    
    def _enumerate(self, domain: str) -> List[str]:
        """Run sublist3r for a single domain"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            temp_output = f.name
        
        try:
            cmd = [
                sys.executable,
                "-m", "sublist3r",
                "-d", domain,
                "-t", str(self.threads),
                "-o", temp_output
            ]
            
            if self.engines and len(self.engines) > 0:
                cmd.extend(["-e", ",".join(self.engines)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
                with open(temp_output, 'r', encoding='utf-8') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                return subdomains
            else:
                if "Total Unique Subdomains Found:" in result.stdout:
                    match = re.search(r'Total Unique Subdomains Found: (\d+)', result.stdout)
                    count = match.group(1) if match else "0"
                    print(f"  [{self.name}] Sublist3r found {count} for {domain}")
                return []
            
        except subprocess.TimeoutExpired:
            print(f"  [{self.name}] Timeout (180s) for {domain}")
            return []
        finally:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except:
                    pass
