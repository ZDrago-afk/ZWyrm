#!/usr/bin/env python3
# utils/config.py - YAML configuration management

import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ZWYRMConfig:
    """Wraps a YAML config file with dot-notation access and deep merge"""

    DEFAULT_CONFIG: Dict[str, Any] = {
        'zwyrm': {
            'version': '2.0',
            'name': 'ZWYRM AntiVirus',
            'author': 'ZWYRM Security Team',
            'license': 'MIT',
            'debug_mode': False,
        },
        'scanning': {
            'max_file_size': 100,
            'scan_depth': 10,
            'max_threads': 4,
            'scan_chunk_size': 8192,
            'exclude_paths': ['/proc', '/sys', '/dev', '/run', '/snap'],
            'exclude_extensions': ['.iso', '.img', '.vmdk', '.vdi', '.qcow2'],
            'quick_scan_paths': ['/tmp', '/var/tmp', '~/Downloads', '~/Desktop'],
            'system_scan_paths': ['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc'],
            'skip_symlinks': True,
            'preserve_file_access_time': True,
        },
        'detection': {
            'enable_signature_based': True,
            'enable_heuristics': True,
            'enable_string_scan': True,
            'enable_entropy_check': True,
            'enable_pe_analysis': True,
            'entropy_threshold': 6.5,
            'max_string_scan_size': 10,
            'suspicious_extensions': [
                '.exe', '.dll', '.so', '.bat', '.cmd', '.vbs', '.js',
                '.ps1', '.sh', '.py', '.pl', '.rb', '.php',
            ],
        },
        'quarantine': {
            'auto_quarantine': True,
            'ask_before_quarantine': False,
            'max_quarantine_size': 1024,
            'max_quarantine_files': 1000,
            'auto_cleanup_days': 30,
            'backup_before_quarantine': True,
        },
        'updates': {
            'auto_update': True,
            'check_on_startup': True,
            'update_check_interval': 24,
            'verify_signatures': False,
            'proxy_enabled': False,
            'proxy_url': '',
            'download_timeout': 30,
        },
        'realtime': {
            'enabled': False,
            'monitor_paths': ['~/Downloads', '~/Desktop', '/tmp'],
            'exclude_paths': ['~/.cache', '~/tmp'],
            'scan_delay': 2,
            'max_concurrent_scans': 2,
            'action_on_detection': 'quarantine',
            'alert_user': True,
        },
        'scheduler': {
            'enabled': False,
            'daily_scan': {'enabled': True, 'time': '02:00', 'type': 'quick'},
            'weekly_scan': {'enabled': True, 'day': 'sunday', 'time': '03:00', 'type': 'full'},
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/zwyrm.log',
            'max_size': 10,
            'backup_count': 5,
            'enable_json_log': True,
            'keep_logs_days': 30,
        },
        'notifications': {
            'enable_desktop_notifications': True,
            'enable_email_alerts': False,
            'alert_on_threat': True,
            'alert_on_update': True,
        },
        'performance': {
            'max_cpu_usage': 80,
            'max_memory_usage': 512,
            'enable_hash_cache': True,
            'cache_ttl': 3600,
            'use_multithreading': True,
            'thread_pool_size': 4,
        },
        'ui': {
            'colors_enabled': True,
            'progress_bar': True,
            'show_scan_details': True,
            'verbose_mode': False,
        },
    }

    def __init__(self, config_file: str = 'config.yaml'):
        self._config_file = self._resolve_config_path(config_file)
        self._data: Dict[str, Any] = self._load()

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_config_path(config_file: str) -> Path:
        """Find config file: explicit → ~/.zwyrm/config.yaml → ./config.yaml"""
        explicit = Path(config_file)
        if explicit.exists():
            return explicit

        user_cfg = Path.home() / '.zwyrm' / 'config.yaml'
        if user_cfg.exists():
            return user_cfg

        return explicit  # Will be created on first save

    # ------------------------------------------------------------------
    # Load / save
    # ------------------------------------------------------------------

    def _load(self) -> Dict[str, Any]:
        """Load config from disk and deep-merge with defaults"""
        if self._config_file.exists():
            try:
                if YAML_AVAILABLE:
                    with open(self._config_file, 'r') as f:
                        on_disk = yaml.safe_load(f) or {}
                else:
                    # Minimal fallback: treat as empty
                    on_disk = {}
                return self._deep_merge(self.DEFAULT_CONFIG, on_disk)
            except Exception as e:
                print(f"Warning: Could not load config ({e}). Using defaults.")

        # No file yet — write defaults
        merged = dict(self.DEFAULT_CONFIG)
        self._save(merged)
        return merged

    def _save(self, data: Optional[Dict] = None):
        """Write config to disk"""
        payload = data if data is not None else self._data
        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            if YAML_AVAILABLE:
                with open(self._config_file, 'w') as f:
                    yaml.dump(payload, f, default_flow_style=False, sort_keys=False)
            else:
                with open(self._config_file, 'w') as f:
                    json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config: {e}")

    def save(self):
        """Public method to save current config"""
        self._save()

    # ------------------------------------------------------------------
    # Deep merge
    # ------------------------------------------------------------------

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        result = dict(base)
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = ZWYRMConfig._deep_merge(result[k], v)
            else:
                result[k] = v
        return result

    # ------------------------------------------------------------------
    # Access API (dot-notation)
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value by dot-notation key, e.g. 'scanning.max_threads'.
        Single-word keys also work: 'debug_mode' looks through all top-level sections.
        """
        parts = key.split('.')
        value: Any = self._data

        # Standard dot-navigation
        try:
            for part in parts:
                value = value[part]
            return value
        except (KeyError, TypeError):
            pass

        # Fallback: search all top-level sections for the key
        if len(parts) == 1:
            for section_val in self._data.values():
                if isinstance(section_val, dict) and key in section_val:
                    return section_val[key]

        return default

    def set(self, key: str, value: Any) -> bool:
        """Set a value by dot-notation key"""
        parts = key.split('.')
        ref = self._data

        try:
            for part in parts[:-1]:
                if part not in ref or not isinstance(ref[part], dict):
                    ref[part] = {}
                ref = ref[part]
            ref[parts[-1]] = value
            self._save()
            return True
        except Exception as e:
            print(f"Config set error: {e}")
            return False

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def expand_paths(self, paths: List[str]) -> List[str]:
        return [os.path.expanduser(os.path.expandvars(p)) for p in paths if isinstance(p, str)]

    def get_scan_config(self) -> Dict:
        cfg = dict(self._data.get('scanning', {}))
        for key in ('exclude_paths', 'quick_scan_paths', 'system_scan_paths'):
            if key in cfg:
                cfg[key] = self.expand_paths(cfg[key])
        return cfg

    def get_realtime_config(self) -> Dict:
        cfg = dict(self._data.get('realtime', {}))
        for key in ('monitor_paths', 'exclude_paths'):
            if key in cfg:
                cfg[key] = self.expand_paths(cfg[key])
        return cfg

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate config and return (ok, errors)"""
        errors: List[str] = []

        for section in ('scanning', 'detection', 'quarantine', 'logging'):
            if section not in self._data:
                errors.append(f"Missing config section: '{section}'")

        threshold = self.get('detection.entropy_threshold', 6.5)
        if not isinstance(threshold, (int, float)) or not (0 <= threshold <= 8):
            errors.append("detection.entropy_threshold must be a number between 0 and 8")

        return len(errors) == 0, errors

    def export_json(self, output_file: str) -> bool:
        try:
            with open(output_file, 'w') as f:
                json.dump(self._data, f, indent=2)
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False

    def import_json(self, input_file: str) -> bool:
        try:
            with open(input_file, 'r') as f:
                imported = json.load(f)
            self._data = self._deep_merge(self._data, imported)
            self._save()
            return True
        except Exception as e:
            print(f"Import error: {e}")
            return False


# ------------------------------------------------------------------
# Module-level singleton helpers
# ------------------------------------------------------------------

_instance: Optional[ZWYRMConfig] = None


def load_config(config_file: str = 'config.yaml') -> ZWYRMConfig:
    global _instance
    if _instance is None:
        _instance = ZWYRMConfig(config_file)
    return _instance


def get_config() -> ZWYRMConfig:
    global _instance
    if _instance is None:
        _instance = ZWYRMConfig()
    return _instance
