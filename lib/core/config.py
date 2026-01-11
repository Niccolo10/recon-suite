"""
Configuration Manager
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigManager:
    """Manages configuration"""
    
    DEFAULTS = {
        'tools': {
            'httpx_path': 'httpx',
            'threads': 50,
            'timeout': 10,
            'retries': 2,
            'ports': [80, 443, 8080, 8443],
            'rate_limit': 150
        },
        'passive': {
            'microsoft_ti': {
                'enabled': False,
                'endpoint_domain': 'https://prod.eur.ti.trafficmanager.net/api/dns/passive/subdomains/export?query={domain}',
                'endpoint_count': 'https://prod.eur.ti.trafficmanager.net/api/dns/passive/subdomains/count?query={domain}',
                'request_interval': 10,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'timeout': 3600,
                'processes_input': []
            },
            'securitytrails': {
                'enabled': False,
                'sec_id': '',
                'endpoint_apex': 'https://securitytrails.com/_next/data/{sec_id}/list/apex_domain/{domain}.json?page={page}&domain={domain}',
                'request_interval': 15,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0',
                'timeout': 3600,
                'processes_input': []
            },
            'crtsh': {
                'enabled': True,
                'timeout': 30
            },
            'sublist3r': {
                'enabled': True,
                'threads': 40,
                'engines': None
            }
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else None
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        if self.config_file and self.config_file.exists():
            user_config = self._load_json(self.config_file)
            return self._deep_merge(self.DEFAULTS.copy(), user_config)
        return self.DEFAULTS.copy()
    
    def _load_json(self, path: Path) -> Dict:
        for encoding in ['utf-8-sig', 'utf-8', 'utf-16', 'latin-1']:
            try:
                with open(path, 'r', encoding=encoding) as f:
                    return json.load(f)
            except (UnicodeDecodeError, UnicodeError):
                continue
        raise ValueError(f"Could not decode: {path}")
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, *keys, default: Any = None) -> Any:
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
