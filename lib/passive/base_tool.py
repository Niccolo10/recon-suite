"""
Base class for all enumeration tools
Provides common interface and utilities
"""

from abc import ABC, abstractmethod
from typing import List, Tuple, Dict
from pathlib import Path


class BaseTool(ABC):
    """Abstract base class for enumeration tools"""

    def __init__(self, config: Dict):
        self.name = "base_tool"
        self.config = config
        self.results = []

    def should_stop(self) -> bool:
        """Check if execution should stop (user pressed q)"""
        try:
            from . import is_stopped
            return is_stopped()
        except ImportError:
            return False
    
    @abstractmethod
    def run(self, domains: List[str]) -> List[Tuple[str, Dict]]:
        """
        Execute the tool on given domains
        
        Args:
            domains: List of domains to enumerate
            
        Returns:
            List of tuples: (subdomain, metadata_dict)
        """
        pass
    
    def save_temp_output(self, data: str, filename: str):
        """Save raw output to temp directory"""
        output_path = Path(self.config.get('output_file', filename))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(data)
    
    def get_timeout(self) -> int:
        return self.config.get('timeout', 600)
    
    def is_enabled(self) -> bool:
        return self.config.get('enabled', False)
