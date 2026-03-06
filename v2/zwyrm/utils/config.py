#!/usr/bin/env python3
# utils/config.py
import yaml, json, os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List  # Use Tuple/List from typing for Python 3.7+ compat

class ZWYRMConfig:
    def __init__(self, config_file='config.yaml'):
        self.config_file = self._find_config(config_file)
        self.default_config = self._get_default_config()
        self.config = self.load_config()

    def _find_config(self, config_file: str) -> Path:
        p = Path(config_file)
        if p.exists(): return p
        user_cfg = Path.home() / '.zwyrm' / 'config.yaml'
        if user_cfg.exists(): return user_cfg
        return p

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            'zwyrm': {'version':'2.0','name':'ZWYRM AntiVirus','debug_mode':False},
            'scanning': {'max_file_size':100,'scan_depth':5,'max_threads':4,'exclude_paths':['/proc','/sys','/dev','/run'],'exclude_extensions':['.iso','.img','.vmdk'],'quick_scan_paths':['/tmp','/var/tmp','~/Downloads','~/Desktop']},
            'detection': {'enable_heuristics':True,'enable_string_scan':True,'entropy_threshold':6.5,'suspicious_extensions':['.exe','.dll','.bat','.cmd','.vbs','.js','.ps1']},
            'quarantine': {'auto_quarantine':True,'max_quarantine_size':1024,'auto_cleanup_days':30},
            'updates': {'auto_update':True,'update_check_interval':24},
            'realtime': {'enabled':False,'monitor_paths':['~/Downloads','~/Desktop','/tmp'],'exclude_paths':['~/.cache']},
            'scheduler': {'enabled':False,'daily_scan_time':'02:00'},
            'logging': {'level':'INFO','file':'logs/zwyrm.log','max_size':10},
            'performance': {'max_concurrent_scans':4,'use_multithreading':True,'cache_ttl':3600}
        }

    def load_config(self) -> Dict[str, Any]:
        if self.config_file.exists():
            try:
                with open(self.config_file) as f: loaded = yaml.safe_load(f) or {}
                return self._deep_merge(self.default_config, loaded)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                return self.default_config
        self.save_config(self.default_config)
        return self.default_config

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        result = base.copy()
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._deep_merge(result[k], v)
            else: result[k] = v
        return result

    def save_config(self, config: Optional[Dict] = None) -> bool:
        if config is None: config = self.config
        try:
            self.config_file.parent.mkdir(exist_ok=True)
            with open(self.config_file, 'w') as f: yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            self.config = config; return True
        except Exception as e: print(f"Error saving config: {e}"); return False

    def get(self, key: str, default=None) -> Any:
        """Get config value using dot notation. Searches all sections for single-word keys."""
        keys = key.split('.')
        value = self.config
        try:
            for k in keys: value = value[k]
            return value
        except (KeyError, TypeError):
            if len(keys) == 1:
                for section in self.config.values():
                    if isinstance(section, dict) and keys[0] in section:
                        return section[keys[0]]
            return default

    def set(self, key: str, value: Any) -> bool:
        keys = key.split('.'); ref = self.config
        try:
            for k in keys[:-1]:
                if k not in ref: ref[k] = {}
                ref = ref[k]
            ref[keys[-1]] = value; self.save_config(); return True
        except Exception as e: print(f"Error setting config: {e}"); return False

    def expand_paths(self, paths: list) -> list:
        return [os.path.expanduser(os.path.expandvars(p)) if isinstance(p,str) else p for p in paths]

    def get_scan_config(self) -> Dict:
        sc = self.get('scanning', {}).copy()
        for key in ('exclude_paths','quick_scan_paths','system_scan_paths'):
            if key in sc: sc[key] = self.expand_paths(sc[key])
        return sc

    def get_realtime_config(self) -> Dict:
        rc = self.get('realtime', {}).copy()
        for key in ('monitor_paths','exclude_paths'):
            if key in rc: rc[key] = self.expand_paths(rc[key])
        return rc

    def validate_config(self) -> Tuple[bool, List]:  # Tuple/List from typing (3.7+ compat)
        errors = []
        for s in ['scanning','detection','quarantine','logging']:
            if s not in self.config: errors.append(f"Missing section: {s}")
        et = self.get('detection.entropy_threshold')
        if et is not None and not (0 <= et <= 8): errors.append("entropy_threshold must be 0-8")
        return len(errors) == 0, errors

    def export_to_json(self, output_file: str) -> bool:
        try:
            with open(output_file,'w') as f: json.dump(self.config, f, indent=2); return True
        except: return False


config_instance = None

def load_config(config_file='config.yaml') -> ZWYRMConfig:
    global config_instance
    if config_instance is None: config_instance = ZWYRMConfig(config_file)
    return config_instance

def get_config() -> ZWYRMConfig:
    global config_instance
    if config_instance is None: config_instance = ZWYRMConfig()
    return config_instance
