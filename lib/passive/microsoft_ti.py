"""
Microsoft Threat Intelligence - Native Implementation
Features:
- Multiple bearer tokens with rotation
- Proxy support per token
- Request delays
- Graceful error handling
"""

import requests
import time
import json
from typing import List, Tuple, Dict
from itertools import cycle
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from termcolor import colored
except ImportError:
    def colored(text, color):
        return text

from .base_tool import BaseTool


class MicrosoftTITool(BaseTool):
    """
    Native Microsoft Threat Intelligence implementation
    """
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "microsoft_ti"
        
        # API endpoints
        self.endpoint_domain = config.get(
            'endpoint_domain',
            'https://prod.eur.ti.trafficmanager.net/api/dns/passive/subdomains/export?query={domain}'
        )
        self.endpoint_count = config.get(
            'endpoint_count',
            'https://prod.eur.ti.trafficmanager.net/api/dns/passive/subdomains/count?query={domain}'
        )
        
        # Process inputs (multiple tokens with proxies)
        self.process_inputs = config.get('processes_input', [])
        if not self.process_inputs:
            raise ValueError("microsoft_ti requires at least one bearer token in 'processes_input'")
        
        # Request settings
        self.request_interval = config.get('request_interval', 10)
        self.user_agent = config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        self.timeout = config.get('timeout', 3600)
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """Run Microsoft TI enumeration with token rotation"""
        print(f"  [{self.name}] Starting with {len(self.process_inputs)} token(s)")
        
        manager = Manager()
        log_lock = manager.Lock()
        results_lock = manager.Lock()
        all_results = manager.list()
        
        token_cycle = cycle(self.process_inputs)
        num_workers = min(len(self.process_inputs), len(domains))
        
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            for domain in domains:
                process_input = next(token_cycle)
                futures.append(
                    executor.submit(
                        self._process_domain,
                        domain,
                        process_input,
                        log_lock,
                        results_lock,
                        all_results
                    )
                )
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self._safe_log(f"  [{self.name}] Worker failed: {e}", log_lock)
        
        return list(all_results)
    
    def _process_domain(self, domain: str, process_input: Dict, log_lock, results_lock, all_results):
        """Process a single domain"""
        bearer_token = process_input.get('authorization', '')
        proxy = process_input.get('proxy', None)
        
        if not bearer_token:
            self._safe_log(f"  [{self.name}] No bearer token for {domain}", log_lock)
            return
        
        session = requests.Session()
        headers = {
            'User-Agent': self.user_agent,
            'Authorization': bearer_token
        }
        
        try:
            # Get count first
            count_url = self.endpoint_count.format(domain=domain)
            count_resp = session.get(
                count_url,
                headers=headers,
                proxies=proxy,
                verify=False,
                timeout=30
            )
            
            if count_resp.status_code == 401:
                self._safe_log(
                    colored(f"  [{self.name}] {domain}: Invalid/expired token", "yellow"),
                    log_lock
                )
                return
            
            if count_resp.status_code != 200:
                self._safe_log(
                    colored(f"  [{self.name}] {domain}: Count failed ({count_resp.status_code})", "red"),
                    log_lock
                )
                return
            
            count_data = count_resp.json()
            total_count = count_data.get('totalCount', 0)
            
            if total_count == 0:
                self._safe_log(
                    colored(f"  [{self.name}] {domain}: No subdomains", "cyan"),
                    log_lock
                )
                return
            
            # Get subdomains
            domain_url = self.endpoint_domain.format(domain=domain)
            data_resp = session.get(
                domain_url,
                headers=headers,
                proxies=proxy,
                verify=False,
                timeout=60
            )
            
            if data_resp.status_code == 401:
                self._safe_log(
                    colored(f"  [{self.name}] {domain}: Token expired during fetch", "yellow"),
                    log_lock
                )
                return
            
            if data_resp.status_code != 200:
                self._safe_log(
                    colored(f"  [{self.name}] {domain}: Data fetch failed ({data_resp.status_code})", "red"),
                    log_lock
                )
                return
            
            # Parse CSV response
            csv_data = data_resp.text
            csv_data = csv_data.replace('"hostname","tags"\n', '')
            
            subdomain_count = 0
            for line in csv_data.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split(',')
                if len(parts) < 1:
                    continue
                
                subdomain = parts[0].strip().strip('"').lower()
                tags = parts[1].strip().strip('"') if len(parts) > 1 else ""
                
                if subdomain:
                    metadata = {
                        'tags': tags,
                        'source': 'microsoft_ti'
                    }
                    with results_lock:
                        all_results.append((subdomain, metadata))
                    subdomain_count += 1
            
            self._safe_log(
                colored(f"  [{self.name}] {domain}: {subdomain_count} subdomains", "green"),
                log_lock
            )
            
            time.sleep(self.request_interval)
            
        except requests.exceptions.Timeout:
            self._safe_log(
                colored(f"  [{self.name}] {domain}: Timeout", "red"),
                log_lock
            )
        except Exception as e:
            self._safe_log(
                colored(f"  [{self.name}] {domain}: {str(e)}", "magenta"),
                log_lock
            )
    
    def _safe_log(self, message: str, lock):
        with lock:
            print(message)
