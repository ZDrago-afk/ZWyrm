#!/usr/bin/env python3
# utils/logger.py - Enhanced logging with rotation and analytics

import logging, logging.handlers, os, sys, hashlib, threading, queue, json, gzip
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional

try:
    import yaml; YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ColoredFormatter(logging.Formatter):
    COLORS = {'DEBUG':'\033[36m','INFO':'\033[32m','WARNING':'\033[33m','ERROR':'\033[31m','CRITICAL':'\033[41m','RESET':'\033[0m'}
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


class EnhancedZWYRMLogger:
    def __init__(self, config_file='config.yaml'):
        self.config = self._load_config(config_file)
        self.loggers = {}; self.queues = {}; self.stats = defaultdict(Counter)
        base = Path.home() / '.zwyrm'
        log_base = base / 'logs' if base.exists() else Path('logs')
        self.log_dir = Path(self.config.get('log_dir', str(log_base)))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._init_loggers()
        self._start_workers()

    def _load_config(self, config_file: str) -> dict:
        defaults = {'log_dir':'logs','log_level':'INFO','enable_json_logs':True,'log_rotation':{'max_bytes':10485760,'backup_count':5,'when':'midnight','interval':1},'analytics':{'retention_days':30,'compress_old_logs':False}}
        if YAML_AVAILABLE:
            try:
                p = Path(config_file)
                if not p.exists(): p = Path.home() / '.zwyrm' / 'config.yaml'
                if p.exists():
                    with open(p) as f: fc = yaml.safe_load(f) or {}
                    if 'logging' in fc:
                        for k, v in fc['logging'].items():
                            if isinstance(v,dict) and k in defaults: defaults[k].update(v)
                            else: defaults[k] = v
            except: pass
        return defaults

    def _init_loggers(self):
        handlers = self._create_handlers()
        configs = {
            'main': (['console','file'], self.config['log_level']),
            'scan': (['scan_file'], 'INFO'),
            'threat': (['threat_file','alert_console'], 'WARNING'),
            'audit': (['audit_file'], 'INFO'),
            'debug': (['debug_file'], 'DEBUG'),
        }
        for name, (handler_names, level) in configs.items():
            lg = logging.getLogger(f'ZWYRM.{name}')
            lg.setLevel(getattr(logging, level))
            lg.handlers = []
            for hn in handler_names:
                if hn in handlers: lg.addHandler(handlers[hn])
            self.loggers[name] = lg
            self.queues[name] = queue.Queue()

    def _create_handlers(self) -> dict:
        h = {}; fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'; dt = '%Y-%m-%d %H:%M:%S'
        cfmt = ColoredFormatter(fmt, datefmt=dt); ffmt = logging.Formatter(fmt, datefmt=dt)
        ch = logging.StreamHandler(sys.stdout); ch.setFormatter(cfmt); h['console'] = ch
        ach = logging.StreamHandler(sys.stderr); ach.setFormatter(cfmt); ach.setLevel(logging.WARNING); h['alert_console'] = ach
        for name, filename in [('file','zwyrm.log'),('scan_file','scans.log'),('threat_file','threats.log'),('audit_file','audit.log'),('debug_file','debug.log')]:
            fh = logging.handlers.RotatingFileHandler(self.log_dir/filename, maxBytes=self.config['log_rotation']['max_bytes'], backupCount=self.config['log_rotation']['backup_count'])
            fh.setFormatter(ffmt); h[name] = fh
        return h

    def _start_workers(self):
        for name in self.queues:
            t = threading.Thread(target=self._worker, args=(name,), daemon=True); t.start()

    def _worker(self, name: str):
        lg = self.loggers[name]; q = self.queues[name]
        while True:
            try:
                record = q.get(timeout=1); lg.handle(record); q.task_done()
            except queue.Empty: continue
            except: pass

    def _log(self, logger_name: str, level: str, message: str):
        if logger_name not in self.loggers: logger_name = 'main'
        lg = self.loggers[logger_name]
        record = lg.makeRecord(lg.name, getattr(logging, level.upper()), '', 0, message, (), None)
        try: self.queues[logger_name].put_nowait(record)
        except queue.Full: lg.handle(record)
        self.stats[logger_name][level] += 1

    # Public API
    def info(self, module: str, message: str): self._log('main', 'INFO', f"[{module}] {message}")
    def warning(self, module: str, message: str): self._log('main', 'WARNING', f"[{module}] {message}")
    def error(self, module: str, message: str): self._log('main', 'ERROR', f"[{module}] {message}")
    def debug(self, module: str, message: str): self._log('debug', 'DEBUG', f"[{module}] {message}")
    def log_error(self, module: str, message: str): self.error(module, message)  # alias

    def log_scan_start(self, scan_type: str, target: str):
        self._log('scan', 'INFO', f"Scan started: {scan_type} on {target}")
        self._append_json('scan_events.json', {'event':'scan_start','timestamp':datetime.now().isoformat(),'scan_type':scan_type,'target':target})

    def log_scan_result(self, results: Dict):
        files = results.get('files_scanned',0); threats = results.get('threats_found',0)
        msg = f"Scan done — files: {files}, threats: {threats}"
        if threats > 0:
            self._log('threat','WARNING',msg)
            for t in results.get('threats',[]): self._log('threat','WARNING',f"Threat: {t.get('filepath')} — {t.get('threats',[])}")
        else: self._log('scan','INFO',msg)
        self._append_json('scan_results.json', {'event':'scan_complete','timestamp':datetime.now().isoformat(),'files_scanned':files,'threats_found':threats,'duration':results.get('duration',0)})

    def log_threat_detection(self, filepath: str, threat_info: Dict, action: str = 'detected'):
        self._log('threat','WARNING',f"Threat {action}: {filepath}")
        self._append_json('threat_detections.json', {'event':'threat_detection','timestamp':datetime.now().isoformat(),'filepath':filepath,'threat_info':threat_info,'action':action})

    def log_quarantine_action(self, action: str, filepath: str, threat_name: str = None):
        self._log('audit','INFO',f"Quarantine {action}: {filepath} ({threat_name or 'Unknown'})")
        self._append_json('quarantine_actions.json', {'event':f'quarantine_{action}','timestamp':datetime.now().isoformat(),'filepath':filepath,'threat_name':threat_name})

    def log_update(self, component: str, version: str, status: str, details: str = None):
        level = 'INFO' if status == 'success' else 'ERROR'
        self._log('audit', level, f"Update {status}: {component} to {version}")

    def log_realtime_event(self, event_type: str, filepath: str, threat_info: Dict = None):
        if threat_info: self._log('threat','WARNING',f"Realtime {event_type}: {filepath} — Threat detected")
        else: self._log('audit','INFO',f"Realtime {event_type}: {filepath}")

    def _append_json(self, filename: str, data: Dict):
        if not self.config.get('enable_json_logs',True): return
        jf = self.log_dir / filename
        try:
            with open(jf, 'a') as f: f.write(json.dumps(data) + '\n')
        except: pass

    def get_recent_logs(self, logger_name: str = 'main', limit: int = 100, level: str = None, module: str = None) -> List[Dict]:
        logs = []
        map_ = {'main':'zwyrm.log','threat':'threats.log','scan':'scans.log','audit':'audit.log'}
        lf = self.log_dir / map_.get(logger_name,'zwyrm.log')
        if not lf.exists(): return logs
        try:
            with open(lf) as f: lines = f.readlines()[-limit:]
            for line in lines:
                parts = line.strip().split(' - ',3)
                if len(parts) >= 4:
                    entry = {'timestamp':parts[0],'name':parts[1],'level':parts[2],'message':parts[3]}
                    if level and entry['level'] != level.upper(): continue
                    if module and module not in entry['message']: continue
                    logs.append(entry)
        except: pass
        return logs

    def get_statistics(self) -> Dict:
        return {'by_logger':{n:dict(c) for n,c in self.stats.items()}}

    def clear_logs(self, logger_name: str = None) -> bool:
        try:
            files = list(self.log_dir.glob('*.log')) + list(self.log_dir.glob('*.json'))
            for f in files: open(f,'w').close()
            return True
        except: return False


_logger_instance = None

def setup_logger(config_file='config.yaml') -> EnhancedZWYRMLogger:
    global _logger_instance
    if _logger_instance is None: _logger_instance = EnhancedZWYRMLogger(config_file)
    return _logger_instance

def get_logger() -> EnhancedZWYRMLogger:
    global _logger_instance
    if _logger_instance is None: _logger_instance = EnhancedZWYRMLogger()
    return _logger_instance

# Backward-compatibility alias
ZWYRMLogger = EnhancedZWYRMLogger
