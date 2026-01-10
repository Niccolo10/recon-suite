"""
Sublist3r tool wrapper
Uses the sublist3r library to enumerate subdomains
"""

import sys
import os
from pathlib import Path
from typing import List, Tuple, Dict
from .base_tool import BaseTool

try:
    import sublist3r
except ImportError:
    print("[WARNING] sublist3r not installed. Install with: pip install sublist3r")
    sublist3r = None


class Sublist3rTool(BaseTool):
    """Sublist3r subdomain enumeration wrapper"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "sublist3r"
        self.threads = config.get('threads', 40)
        self.engines = config.get('engines', None)
        self.enable_bruteforce = config.get('enable_bruteforce', False)
        self.output_file = config.get('output_file', './output/temp/sublist3r_subdomains.txt')
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """
        Run Sublist3r on each domain
        
        Args:
            domains: List of domains to enumerate
            
        Returns:
            List of (subdomain, metadata) tuples
        """
        if sublist3r is None:
            print(f"[{self.name}] Skipping - sublist3r not installed")
            return []
        
        all_results = []
        
        for domain in domains:
            print(f"[{self.name}] Enumerating {domain}...")
            
            try:
                # Suppress sublist3r's output
                original_stdout = sys.stdout
                devnull = open(os.devnull, 'w')
                sys.stdout = devnull
                
                subdomains = sublist3r.main(
                    domain=domain,
                    threads=self.threads,
                    savefile=None,  # We'll save ourselves
                    ports=None,
                    silent=True,
                    verbose=False,
                    enable_bruteforce=self.enable_bruteforce,
                    engines=self.engines
                )
                
                # Restore stdout
                devnull.close()
                sys.stdout = original_stdout
                
                if subdomains:
                    print(f"[{self.name}] Found {len(subdomains)} subdomains for {domain}")
                    
                    for subdomain in subdomains:
                        metadata = {
                            'source': 'sublist3r',
                            'parent_domain': domain
                        }
                        all_results.append((subdomain.lower(), metadata))
                else:
                    print(f"[{self.name}] No subdomains found for {domain}")
                
            except Exception as e:
                # Restore stdout in case of error
                sys.stdout = original_stdout
                print(f"[{self.name}] Error enumerating {domain}: {str(e)}")
                continue
        
        # Save results
        self._save_results(all_results)
        
        return all_results
    
    def _save_results(self, results: List[Tuple[str, Dict]]):
        """Save results to text file"""
        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for subdomain, _ in results:
                f.write(f"{subdomain}\n")
        
        print(f"[{self.name}] Results saved to: {self.output_file}")