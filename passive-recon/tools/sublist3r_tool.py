"""
Sublist3r tool wrapper - Production version
Uses all available sources, gracefully handles failures
"""
import sys
import os
import subprocess
import re
from pathlib import Path
from typing import List, Tuple, Dict
from .base_tool import BaseTool

try:
    import sublist3r
except ImportError:
    sublist3r = None


class Sublist3rTool(BaseTool):
    """Sublist3r subdomain enumeration wrapper - Production ready"""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "sublist3r"
        self.threads = config.get('threads', 40)
        self.engines = config.get('engines', None)
        self.enable_bruteforce = config.get('enable_bruteforce', False)
        self.output_file = config.get('output_file', './output/temp/sublist3r_subdomains.txt')
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """
        Run Sublist3r on domains using subprocess
        
        Sublist3r sources (when no -e specified):
        - Google, Bing, Yahoo, Baidu, Ask (search engines)
        - Netcraft, Virustotal, ThreatCrowd (threat intel)
        - DNSdumpster, SSL Certificates, PassiveDNS (DNS/SSL)
        
        Some sources may be rate-limited, but others will succeed.
        """
        if sublist3r is None:
            print(f"[{self.name}] Skipping - sublist3r not installed")
            return []
        
        all_results = []
        
        # Use absolute path for temp directory
        temp_dir = os.path.abspath("./output/temp")
        os.makedirs(temp_dir, exist_ok=True)
        
        for domain in domains:
            print(f"[{self.name}] Enumerating {domain}...")
            
            temp_output = os.path.join(temp_dir, f"sublist3r_{domain}.txt")
            
            try:
                # Build command
                cmd = [
                    sys.executable,
                    "-m", "sublist3r",
                    "-d", domain,
                    "-t", str(self.threads),
                    "-o", temp_output
                ]
                
                # Only add engines if specifically configured
                # If None, Sublist3r will try all available sources
                if self.engines and len(self.engines) > 0:
                    cmd.extend(["-e", ",".join(self.engines)])
                
                # Run with timeout
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=180  # 3 minutes timeout
                )
                
                # Parse results from file
                if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
                    with open(temp_output, 'r', encoding='utf-8') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                    
                    print(f"[{self.name}] Found {len(subdomains)} subdomains for {domain}")
                    
                    for subdomain in subdomains:
                        metadata = {
                            'source': 'sublist3r',
                            'parent_domain': domain
                        }
                        all_results.append((subdomain.lower(), metadata))
                    
                    # Clean up temp file
                    os.remove(temp_output)
                else:
                    # No results - check if sublist3r reported anything
                    if "Total Unique Subdomains Found:" in result.stdout:
                        match = re.search(r'Total Unique Subdomains Found: (\d+)', result.stdout)
                        count = match.group(1) if match else "0"
                        print(f"[{self.name}] Sublist3r completed but found {count} subdomains for {domain}")
                    else:
                        print(f"[{self.name}] No subdomains found for {domain}")
                    
                    # Clean up empty file if exists
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                
            except subprocess.TimeoutExpired:
                print(f"[{self.name}] Timeout after 180s for {domain}")
                if os.path.exists(temp_output):
                    os.remove(temp_output)
            except Exception as e:
                print(f"[{self.name}] Error enumerating {domain}: {str(e)}")
                if os.path.exists(temp_output):
                    try:
                        os.remove(temp_output)
                    except:
                        pass
                continue
        
        # Save aggregated results
        self._save_results(all_results)
        
        return all_results
    
    def _save_results(self, results: List[Tuple[str, Dict]]):
        """Save results to text file"""
        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            for subdomain, _ in results:
                f.write(f"{subdomain}\n")
        
        if results:
            print(f"[{self.name}] Saved {len(results)} unique subdomains to {self.output_file}")