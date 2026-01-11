"""
Project Manager
Handles project creation, loading, and management.
"""

import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional


class ProjectManager:
    """Manages recon projects"""
    
    def __init__(self, base_path: Optional[Path] = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = Path(__file__).parent.parent.parent
        
        self.projects_dir = self.base_path / 'projects'
        self.templates_dir = self.base_path / 'templates'
        self.projects_dir.mkdir(parents=True, exist_ok=True)
    
    def create_project(self, name: str) -> Path:
        """Create a new project"""
        if not name or not name.replace('-', '').replace('_', '').isalnum():
            raise ValueError(f"Invalid project name: {name}")
        
        project_path = self.projects_dir / name
        
        if project_path.exists():
            raise FileExistsError(f"Project exists: {name}")
        
        # Create structure
        project_path.mkdir(parents=True)
        for phase in ['phase1', 'phase2', 'phase3', 'phase4', 'phase5']:
            (project_path / phase).mkdir()
        
        # Copy templates
        scope_template = self.templates_dir / 'scope.json.example'
        domains_template = self.templates_dir / 'domains.txt.example'
        
        if scope_template.exists():
            shutil.copy(scope_template, project_path / 'scope.json')
        else:
            # Create default scope
            scope = {
                "name": f"{name} Bug Bounty",
                "in_scope": [f"*.{name}.com"],
                "out_of_scope": []
            }
            with open(project_path / 'scope.json', 'w', encoding='utf-8') as f:
                json.dump(scope, f, indent=2)
        
        if domains_template.exists():
            shutil.copy(domains_template, project_path / 'domains.txt')
        else:
            with open(project_path / 'domains.txt', 'w', encoding='utf-8') as f:
                f.write(f"# Add target domains (one per line)\n")
                f.write(f"# {name}.com\n")
        
        return project_path
    
    def load_project(self, name: str) -> Dict:
        """Load a project"""
        project_path = self.projects_dir / name
        
        if not project_path.exists():
            raise FileNotFoundError(f"Project not found: {name}")
        
        # Load scope
        scope_file = project_path / 'scope.json'
        scope = self._load_json(scope_file) if scope_file.exists() else {}
        
        # Load domains
        domains_file = project_path / 'domains.txt'
        domains = self._load_domains(domains_file) if domains_file.exists() else []
        
        # Load global config
        config = self._load_global_config()
        
        return {
            'name': name,
            'path': project_path,
            'scope': scope,
            'domains': domains,
            'config': config,
            'phases': {
                'phase1': project_path / 'phase1',
                'phase2': project_path / 'phase2',
                'phase3': project_path / 'phase3',
                'phase4': project_path / 'phase4',
                'phase5': project_path / 'phase5'
            }
        }
    
    def list_projects(self) -> List[str]:
        """List all projects"""
        if not self.projects_dir.exists():
            return []
        return sorted([
            p.name for p in self.projects_dir.iterdir() 
            if p.is_dir() and not p.name.startswith('.')
        ])
    
    def _load_json(self, path: Path) -> Dict:
        """Load JSON with encoding handling"""
        for encoding in ['utf-8-sig', 'utf-8', 'utf-16', 'latin-1']:
            try:
                with open(path, 'r', encoding=encoding) as f:
                    return json.load(f)
            except (UnicodeDecodeError, UnicodeError):
                continue
        raise ValueError(f"Could not decode: {path}")
    
    def _load_domains(self, path: Path) -> List[str]:
        """Load domains from text file"""
        domains = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
        return domains
    
    def _load_global_config(self) -> Dict:
        """Load global config.json"""
        config_file = self.base_path / 'config.json'
        
        if config_file.exists():
            return self._load_json(config_file)
        
        # Defaults
        return {
            'tools': {
                'httpx_path': 'httpx',
                'threads': 50,
                'timeout': 10,
                'ports': [80, 443, 8080, 8443],
                'rate_limit': 150
            },
            'passive': {
                'microsoft_ti': {'enabled': False},
                'securitytrails': {'enabled': False},
                'crtsh': {'enabled': True},
                'sublist3r': {'enabled': True}
            }
        }
