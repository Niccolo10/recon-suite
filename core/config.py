"""
Configuration Manager
Handles loading and validating configuration for all phases.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigManager:
    """
    Manages configuration loading and validation.
    Provides defaults for missing values.
    """
    
    # Default configuration values
    DEFAULTS = {
        'phase2': {
            'httpx': {
                'threads': 50,
                'timeout': 10,
                'retries': 2,
                'follow_redirects': True,
                'ports': [80, 443, 8080, 8443],
                'rate_limit': 150  # requests per second
            },
            'output_dir': './phase2-resolution'
        },
        'phase3': {
            'js_analyzer': {
                'timeout': 30,
                'max_file_size_mb': 10,
                'extract_secrets': False  # High false positive rate
            },
            'wayback': {
                'rate_limit': 2,  # requests per second (be nice to archive.org)
                'timeout': 30
            },
            'output_dir': './phase3-discovery'
        },
        'phase4': {
            'reflection': {
                'timeout': 10,
                'canary_prefix': 'RFLCT'
            },
            'output_dir': './phase4-analysis'
        },
        'phase5': {
            'takeover': {
                'timeout': 10,
                'verify_vulnerability': True
            },
            'output_dir': './phase5-vulns'
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to config.json (optional, uses defaults if not provided)
        """
        self.config_file = Path(config_file) if config_file else None
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration, merging with defaults"""
        if self.config_file and self.config_file.exists():
            # Try different encodings (handles Windows BOM issues)
            encodings = ['utf-8-sig', 'utf-8', 'utf-16', 'latin-1']
            user_config = None
            
            for encoding in encodings:
                try:
                    with open(self.config_file, 'r', encoding=encoding) as f:
                        user_config = json.load(f)
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON in config file: {e}")
            
            if user_config is None:
                raise ValueError(f"Could not decode config file with any supported encoding")
            
            # Deep merge with defaults
            config = self._deep_merge(self.DEFAULTS.copy(), user_config)
            print(f"[CONFIG] Loaded: {self.config_file}")
        else:
            config = self.DEFAULTS.copy()
            if self.config_file:
                print(f"[CONFIG] File not found, using defaults: {self.config_file}")
            else:
                print("[CONFIG] Using default configuration")
        
        return config
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """
        Deep merge two dictionaries.
        Override values take precedence.
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, *keys, default: Any = None) -> Any:
        """
        Get nested configuration value.
        
        Args:
            *keys: Path to config value (e.g., 'phase2', 'httpx', 'threads')
            default: Default value if path not found
            
        Returns:
            Configuration value or default
        """
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def get_phase2_config(self) -> Dict:
        """Get Phase 2 (resolution) configuration"""
        return self.config.get('phase2', self.DEFAULTS['phase2'])
    
    def get_phase3_config(self) -> Dict:
        """Get Phase 3 (discovery) configuration"""
        return self.config.get('phase3', self.DEFAULTS['phase3'])
    
    def get_phase4_config(self) -> Dict:
        """Get Phase 4 (analysis) configuration"""
        return self.config.get('phase4', self.DEFAULTS['phase4'])
    
    def get_phase5_config(self) -> Dict:
        """Get Phase 5 (vuln checks) configuration"""
        return self.config.get('phase5', self.DEFAULTS['phase5'])
    
    def save_template(self, output_path: str):
        """Save default configuration as template"""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(self.DEFAULTS, f, indent=2)
        
        print(f"[CONFIG] Template saved: {output}")


def create_config_template(output_path: str = "./config.json"):
    """Create a configuration template file"""
    manager = ConfigManager()
    manager.save_template(output_path)
    return output_path


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "create-template":
        output = sys.argv[2] if len(sys.argv) > 2 else "./config.json"
        create_config_template(output)
    else:
        print("Usage:")
        print("  python config.py create-template [output_path]")
