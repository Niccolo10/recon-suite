#!/usr/bin/env python3
"""
Master Subdomain Enumeration Orchestrator
Coordinates multiple passive enumeration tools and produces unified output
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple
import traceback

# Import tool wrappers
from tools.microsoft_ti import MicrosoftTITool
from tools.securitytrails import SecurityTrailsTool
from tools.crtsh_tool import CrtshTool
from tools.sublist3r_tool import Sublist3rTool

# Import utilities
from utils.deduplicator import Deduplicator
from utils.validator import DomainValidator
from utils.merger import ResultsMerger


class MasterEnumerator:
    def __init__(self, config_path: str = "config.json"):
        """Initialize the master enumerator with configuration"""
        self.config = self._load_config(config_path)
        self.domains = []
        self.checkpoint_file = Path(self.config['output']['checkpoint_dir']) / 'state.json'
        self.results = {}
        self.validator = DomainValidator()
        self.deduplicator = Deduplicator(self.config['deduplication'])
        self.merger = ResultsMerger(self.config['output'])
        
        # Create necessary directories
        self._setup_directories()
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def _setup_directories(self):
        """Create output directories if they don't exist"""
        dirs = [
            self.config['output']['temp_dir'],
            self.config['output']['checkpoint_dir'],
            Path(self.config['output']['final_results']).parent
        ]
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    def _load_domains(self) -> List[str]:
        """Load and validate input domains"""
        domains_file = self.config['input']['domains_file']
        
        if not os.path.exists(domains_file):
            raise FileNotFoundError(f"Domains file not found: {domains_file}")
        
        with open(domains_file, 'r') as f:
            raw_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Validate and normalize domains
        valid_domains = []
        for domain in raw_domains:
            normalized = self.validator.normalize(domain)
            if self.validator.is_valid_domain(normalized):
                valid_domains.append(normalized)
            else:
                print(f"[WARNING] Invalid domain skipped: {domain}")
        
        return valid_domains
    
    def _load_checkpoint(self) -> Dict:
        """Load checkpoint if resume is enabled"""
        if not self.config['input']['resume_from_checkpoint']:
            return None
        
        if not self.checkpoint_file.exists():
            return None
        
        try:
            with open(self.checkpoint_file, 'r') as f:
                checkpoint = json.load(f)
                print(f"[INFO] Resuming from checkpoint: {checkpoint['timestamp']}")
                return checkpoint
        except Exception as e:
            print(f"[WARNING] Failed to load checkpoint: {e}")
            return None
    
    def _save_checkpoint(self, completed_tools: List[str], results: Dict):
        """Save current state to checkpoint"""
        checkpoint = {
            'timestamp': datetime.now().isoformat(),
            'completed_tools': completed_tools,
            'domains_processed': self.domains,
            'results_count': {tool: len(data) for tool, data in results.items()}
        }
        
        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)
        
        print(f"[CHECKPOINT] State saved at {checkpoint['timestamp']}")
    
    def _initialize_tools(self) -> Dict:
        """Initialize all enabled tools"""
        tools = {}
        tool_config = self.config['tools']
        
        if tool_config.get('microsoft_ti', {}).get('enabled', False):
            tools['microsoft_ti'] = MicrosoftTITool(tool_config['microsoft_ti'])
        
        if tool_config.get('securitytrails', {}).get('enabled', False):
            tools['securitytrails'] = SecurityTrailsTool(tool_config['securitytrails'])
        
        if tool_config.get('crtsh', {}).get('enabled', False):
            tools['crtsh'] = CrtshTool(tool_config['crtsh'])
        
        if tool_config.get('sublist3r', {}).get('enabled', False):
            tools['sublist3r'] = Sublist3rTool(tool_config['sublist3r'])
        
        return tools
    
    def _run_tool(self, tool_name: str, tool_instance, domains: List[str]) -> Tuple[str, List, Dict]:
        """Run a single tool and return results"""
        print(f"\n{'='*60}")
        print(f"[START] Running {tool_name}")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        try:
            results = tool_instance.run(domains)
            elapsed = time.time() - start_time
            
            stats = {
                'success': True,
                'subdomains_found': len(results),
                'elapsed_seconds': round(elapsed, 2),
                'timestamp': datetime.now().isoformat()
            }
            
            print(f"[SUCCESS] {tool_name}: Found {len(results)} subdomains in {elapsed:.2f}s")
            return (tool_name, results, stats)
            
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"[ERROR] {tool_name} failed: {str(e)}")
            traceback.print_exc()
            
            stats = {
                'success': False,
                'error': str(e),
                'elapsed_seconds': round(elapsed, 2),
                'timestamp': datetime.now().isoformat()
            }
            
            return (tool_name, [], stats)
    
    def run_passive_enumeration(self):
        """Main execution flow"""
        print("\n" + "="*60)
        print("PASSIVE SUBDOMAIN ENUMERATION - MASTER ORCHESTRATOR")
        print("="*60)
        
        # Step 1: Load domains
        print("\n[STEP 1] Loading input domains...")
        self.domains = self._load_domains()
        print(f"[INFO] Loaded {len(self.domains)} valid domains: {', '.join(self.domains)}")
        
        # Step 2: Check checkpoint
        checkpoint = self._load_checkpoint()
        completed_tools = checkpoint['completed_tools'] if checkpoint else []
        
        # Step 3: Initialize tools
        print("\n[STEP 2] Initializing tools...")
        all_tools = self._initialize_tools()
        
        # Filter out already completed tools if resuming
        tools_to_run = {
            name: tool for name, tool in all_tools.items() 
            if name not in completed_tools
        }
        
        if not tools_to_run:
            print("[INFO] All tools already completed (from checkpoint)")
        else:
            print(f"[INFO] Tools to run: {', '.join(tools_to_run.keys())}")
        
        # Step 4: Run tools in parallel
        print("\n[STEP 3] Running passive enumeration tools...")
        
        tool_results = {}
        tool_stats = {}
        
        if self.config['execution']['parallel_tools']:
            # Run all tools in parallel
            max_workers = min(
                self.config['execution']['max_workers'],
                len(tools_to_run)
            )
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._run_tool, name, tool, self.domains): name
                    for name, tool in tools_to_run.items()
                }
                
                for future in as_completed(futures):
                    tool_name, results, stats = future.result()
                    tool_results[tool_name] = results
                    tool_stats[tool_name] = stats
                    
                    # Save checkpoint after each tool completes
                    completed_tools.append(tool_name)
                    self._save_checkpoint(completed_tools, tool_results)
        else:
            # Run tools sequentially
            for tool_name, tool_instance in tools_to_run.items():
                tool_name, results, stats = self._run_tool(tool_name, tool_instance, self.domains)
                tool_results[tool_name] = results
                tool_stats[tool_name] = stats
                
                # Save checkpoint after each tool
                completed_tools.append(tool_name)
                self._save_checkpoint(completed_tools, tool_results)
        
        # Step 5: Aggregate and deduplicate
        print("\n[STEP 4] Aggregating and deduplicating results...")
        all_subdomains = self.deduplicator.process(tool_results)
        print(f"[INFO] Total unique subdomains: {len(all_subdomains)}")
        
        # Step 6: Merge and create final output
        print("\n[STEP 5] Creating final output...")
        final_output = self.merger.create_final_output(all_subdomains, self.domains)
        
        # Step 7: Save metadata
        metadata = {
            'execution_time': datetime.now().isoformat(),
            'input_domains': self.domains,
            'tool_statistics': tool_stats,
            'total_subdomains_found': len(all_subdomains),
            'output_file': self.config['output']['final_results']
        }
        
        metadata_file = self.config['output']['metadata_file']
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\n[SUCCESS] Metadata saved to: {metadata_file}")
        print(f"[SUCCESS] Final results saved to: {final_output}")
        
        # Step 8: Print summary
        self._print_summary(tool_stats, len(all_subdomains))
        
        # Clean checkpoint
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()
            print("\n[INFO] Checkpoint cleaned up")
    
    def _print_summary(self, tool_stats: Dict, total_subdomains: int):
        """Print execution summary"""
        print("\n" + "="*60)
        print("EXECUTION SUMMARY")
        print("="*60)
        
        for tool_name, stats in tool_stats.items():
            status = "✓ SUCCESS" if stats['success'] else "✗ FAILED"
            print(f"\n{tool_name}:")
            print(f"  Status: {status}")
            if stats['success']:
                print(f"  Subdomains Found: {stats['subdomains_found']}")
            else:
                print(f"  Error: {stats.get('error', 'Unknown')}")
            print(f"  Time Elapsed: {stats['elapsed_seconds']}s")
        
        print(f"\n{'='*60}")
        print(f"TOTAL UNIQUE SUBDOMAINS: {total_subdomains}")
        print(f"{'='*60}\n")


def main():
    """Entry point"""
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    
    try:
        enumerator = MasterEnumerator(config_file)
        enumerator.run_passive_enumeration()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Progress saved to checkpoint.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()