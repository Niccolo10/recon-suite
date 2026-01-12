"""
SecurityTrails - Native Implementation with Progressive Saving
Features:
- Multiple cookies with rotation
- Saves after each page (never lose progress)
- Proxy support per cookie
- Request delays and pagination
- 403/Cloudflare error detection
"""

import requests
import time
import json
import re
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


class SecurityTrailsTool(BaseTool):
    """
    Native SecurityTrails implementation with progressive saving
    """
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "securitytrails"
        
        # API settings
        self.sec_id = config.get('sec_id', '')
        if not self.sec_id:
            raise ValueError("securitytrails requires 'sec_id' in config")
        
        # Endpoints
        self.endpoint_apex = config.get(
            'endpoint_apex',
            'https://securitytrails.com/_next/data/{sec_id}/list/apex_domain/{domain}.json?page={page}&domain={domain}'
        )
        self.endpoint_ip = config.get(
            'endpoint_ip',
            'https://securitytrails.com/_next/data/{sec_id}/list/ip/{ip}.json?page={page}&ip={ip}'
        )
        
        # Process inputs (multiple cookies with proxies)
        self.process_inputs = config.get('processes_input', [])
        if not self.process_inputs:
            raise ValueError("securitytrails requires at least one cookie in 'processes_input'")
        
        print(f"  [{self.name}] Loaded {len(self.process_inputs)} cookie(s)")
        
        # Request settings
        self.request_interval = config.get('request_interval', 15)
        self.user_agent = config.get(
            'user_agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0'
        )
        self.timeout = config.get('timeout', 3600)
    
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """Run SecurityTrails enumeration with cookie rotation"""
        print(f"  [{self.name}] Starting with {len(self.process_inputs)} cookie(s)")
        
        manager = Manager()
        log_lock = manager.Lock()
        results_lock = manager.Lock()
        all_results = manager.list()
        
        cookie_cycle = cycle(self.process_inputs)
        num_workers = min(len(self.process_inputs), len(domains))
        
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            for domain in domains:
                process_input = next(cookie_cycle)
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
    
    def _is_ip_address(self, s: str) -> bool:
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s))
    
    def _parse_cookies(self, cookie_str: str) -> Dict:
        cookies = {}
        for cookie in cookie_str.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
        return cookies
    
    def _process_domain(self, domain_or_ip: str, process_input: Dict, log_lock, results_lock, all_results):
        """Process a single domain/IP with pagination"""
        cookie_str = process_input.get('cookie', '')
        proxy = process_input.get('proxy', None)

        if not cookie_str:
            self._safe_log(f"  [{self.name}] No cookie for {domain_or_ip}", log_lock)
            return

        session = requests.Session()
        cookies = self._parse_cookies(cookie_str)

        # Full browser-like headers to avoid Cloudflare detection
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9,it;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://securitytrails.com/',
            'Origin': 'https://securitytrails.com',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-CH-UA': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
        }
        
        is_ip = self._is_ip_address(domain_or_ip)
        endpoint_template = self.endpoint_ip if is_ip else self.endpoint_apex
        
        page = 1
        total_pages = 1
        count = 0
        
        while page <= total_pages:
            try:
                url = endpoint_template.format(
                    sec_id=self.sec_id,
                    domain=domain_or_ip,
                    ip=domain_or_ip,
                    page=page
                )
                
                response = session.get(
                    url,
                    headers=headers,
                    cookies=cookies,
                    proxies=proxy,
                    verify=False,
                    timeout=30
                )
                
                if response.status_code == 403:
                    self._safe_log(
                        colored(f"  [{self.name}] {domain_or_ip} page {page}: 403 (Cloudflare)", "red"),
                        log_lock
                    )
                    break
                
                if response.status_code != 200:
                    self._safe_log(
                        colored(f"  [{self.name}] {domain_or_ip} page {page}: {response.status_code}", "red"),
                        log_lock
                    )
                    break
                
                data = response.json()
                body = data.get('pageProps', {})
                
                if is_ip:
                    body = body.get('serverResponse', {}).get('data', {})
                else:
                    body = body.get('apexDomainData', {}).get('data', {})
                
                if page == 1:
                    total_pages = int(body.get('meta', {}).get('total_pages', 1))
                
                records = body.get('records', [])
                for record in records:
                    hostname = record.get('hostname', '').strip().lower()
                    if not hostname:
                        continue
                    
                    host_provider = ','.join(record.get('host_provider', []))
                    mail_provider = ','.join(record.get('mail_provider', []))
                    
                    metadata = {
                        'host_provider': host_provider,
                        'mail_provider': mail_provider,
                        'source': 'securitytrails'
                    }
                    
                    with results_lock:
                        all_results.append((hostname, metadata))
                    count += 1
                
                self._safe_log(
                    colored(f"  [{self.name}] {domain_or_ip} page {page}/{total_pages} ({count} total)", "green"),
                    log_lock
                )
                
                page += 1
                if page <= total_pages:
                    time.sleep(2)
                
            except requests.exceptions.Timeout:
                self._safe_log(
                    colored(f"  [{self.name}] {domain_or_ip} page {page}: Timeout", "red"),
                    log_lock
                )
                break
            except Exception as e:
                self._safe_log(
                    colored(f"  [{self.name}] {domain_or_ip} page {page}: {str(e)}", "magenta"),
                    log_lock
                )
                break
        
        time.sleep(self.request_interval)
    
    def _safe_log(self, message: str, lock):
        with lock:
            print(message)
