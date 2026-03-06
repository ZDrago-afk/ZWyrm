#!/usr/bin/env python3
# utils/logger.py - Structured rotating logger with async queue support

import logging
import logging.handlers
import sys
import os
import json
import gzip
import hashlib
import threading
import queue
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class ColoredFormatter(logging.Formatter):
    """Console formatter with ANSI colour codes"""

    COLORS = {
        'DEBUG':    '\033[36m',
        'INFO':     '\033[32m',
        'WARNING':  '\033[33m',
        'ERROR':    '\033[31m',
        'CRITICAL': '\033[41m',
        'RESET':    '\033[0m',
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, '')
        reset = self.COLORS['RESET']
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


class EnhancedZWYRMLogger:
    def __init__(self, config_file: str = 'config.yaml'):
        self.config = self._load_config(config_file)

        self.log_dir = Path(self.config.get('log_dir', 'logs'))
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.loggers: Dict[str, logging.Logger] = {}
        self.queues: Dict[str, queue.Queue] = {}
        self.stats: Dict[str, Counter] = defaultdict(Counter)

        self._init_loggers()
        self._start_queue_workers()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        defaults: Dict[str, Any] = {
            'log_dir': 'logs',
            'log_level': 'INFO',
            'enable_syslog': False,
            'enable_json_logs': True,
            'log_rotation': {
                'max_bytes': 10 * 1024 * 1024,  # 10 MB
                'backup_count': 5,
                'when': 'midnight',
                'interval': 1,
            },
            'analytics': {
                'retention_days': 30,
                'compress_old_logs': False,
            },
        }

        if YAML_AVAILABLE:
            for candidate in [config_file, 'config.yaml',
                               str(Path.home() / '.zwyrm' / 'config.yaml')]:
                if os.path.exists(candidate):
                    try:
                        with open(candidate, 'r') as f:
                            raw = yaml.safe_load(f) or {}
                        for k, v in raw.get('logging', {}).items():
                            if isinstance(v, dict) and k in defaults and isinstance(defaults[k], dict):
                                defaults[k].update(v)
                            else:
                                defaults[k] = v
                        break
                    except Exception:
                        pass

        return defaults

    # ------------------------------------------------------------------
    # Logger & handler initialisation
    # ------------------------------------------------------------------

    def _init_loggers(self):
        handlers = self._build_handlers()

        logger_map = {
            'main':        ['console', 'file'],
            'scan':        ['scan_file'],
            'threat':      ['threat_file', 'alert_console'],
            'audit':       ['audit_file'],
            'performance': ['perf_file'],
            'debug':       ['debug_file'],
        }

        for name, handler_names in logger_map.items():
            logger = logging.getLogger(f'ZWYRM.{name}')
            logger.setLevel(getattr(logging, self.config.get('log_level', 'INFO'), logging.INFO))
            logger.handlers = []
            logger.propagate = False

            for hn in handler_names:
                if hn in handlers:
                    logger.addHandler(handlers[hn])

            self.loggers[name] = logger
            self.queues[name] = queue.Queue(maxsize=10000)

    def _build_handlers(self) -> Dict[str, logging.Handler]:
        rot = self.config['log_rotation']
        fmt_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        date_fmt = '%Y-%m-%d %H:%M:%S'
        plain_fmt = logging.Formatter(fmt_str, datefmt=date_fmt)
        color_fmt = ColoredFormatter(fmt_str, datefmt=date_fmt)

        handlers: Dict[str, logging.Handler] = {}

        # Console
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(color_fmt)
        handlers['console'] = ch

        # Alert console (stderr, WARNING+)
        ach = logging.StreamHandler(sys.stderr)
        ach.setFormatter(color_fmt)
        ach.setLevel(logging.WARNING)
        handlers['alert_console'] = ach

        def make_rotating(filename: str) -> logging.Handler:
            fh = logging.handlers.RotatingFileHandler(
                self.log_dir / filename,
                maxBytes=rot['max_bytes'],
                backupCount=rot['backup_count'],
                encoding='utf-8',
            )
            fh.setFormatter(plain_fmt)
            return fh

        def make_timed(filename: str) -> logging.Handler:
            fh = logging.handlers.TimedRotatingFileHandler(
                self.log_dir / filename,
                when=rot.get('when', 'midnight'),
                interval=rot.get('interval', 1),
                backupCount=rot.get('backup_count', 5),
                encoding='utf-8',
            )
            fh.setFormatter(plain_fmt)
            return fh

        handlers['file']        = make_rotating('zwyrm.log')
        handlers['scan_file']   = make_timed('scans.log')
        handlers['threat_file'] = make_rotating('threats.log')
        handlers['audit_file']  = make_rotating('audit.log')
        handlers['perf_file']   = make_rotating('performance.log')
        handlers['debug_file']  = make_rotating('debug.log')

        # Syslog (optional)
        if self.config.get('enable_syslog', False):
            try:
                sl = logging.handlers.SysLogHandler(
                    address=self.config.get('syslog_address', '/dev/log')
                )
                sl.setFormatter(logging.Formatter('ZWYRM: %(levelname)s - %(message)s'))
                handlers['syslog'] = sl
            except Exception:
                pass

        return handlers

    # ------------------------------------------------------------------
    # Queue workers (async logging)
    # ------------------------------------------------------------------

    def _start_queue_workers(self):
        for name in self.queues:
            t = threading.Thread(target=self._worker, args=(name,), daemon=True)
            t.start()

    def _worker(self, name: str):
        logger = self.loggers[name]
        q = self.queues[name]
        while True:
            try:
                record = q.get(timeout=1.0)
                logger.handle(record)
                q.task_done()
            except queue.Empty:
                continue
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Core logging API
    # ------------------------------------------------------------------

    def _log(self, logger_name: str, level: int, message: str):
        if logger_name not in self.loggers:
            logger_name = 'main'
        logger = self.loggers[logger_name]

        record = logger.makeRecord(
            name=logger.name,
            level=level,
            fn='',
            lno=0,
            msg=message,
            args=(),
            exc_info=None,
        )

        try:
            self.queues[logger_name].put_nowait(record)
        except queue.Full:
            logger.handle(record)  # synchronous fallback

        level_name = logging.getLevelName(level)
        self.stats[logger_name][level_name] += 1

    def debug(self, module: str, message: str):
        self._log('debug', logging.DEBUG, f'[{module}] {message}')

    def info(self, module: str, message: str):
        self._log('main', logging.INFO, f'[{module}] {message}')

    def warning(self, module: str, message: str):
        self._log('main', logging.WARNING, f'[{module}] {message}')

    def error(self, module: str, message: str):
        self._log('main', logging.ERROR, f'[{module}] {message}')

    def critical(self, module: str, message: str):
        self._log('main', logging.CRITICAL, f'[{module}] {message}')

    # Alias so callers can do logger.log_error(msg, module)
    def log_error(self, message: str, module: str = 'system'):
        self.error(module, message)

    # ------------------------------------------------------------------
    # Domain-specific log helpers
    # ------------------------------------------------------------------

    def log_scan_start(self, scan_type: str, target: str):
        msg = f"Scan started: type={scan_type} target={target}"
        self._log('scan', logging.INFO, msg)

    def log_scan_result(self, results: Dict):
        files = results.get('files_scanned', 0)
        threats = results.get('threats_found', 0)
        duration = results.get('duration', 0)

        msg = f"Scan complete — files={files} threats={threats} duration={duration:.1f}s"

        if threats > 0:
            self._log('threat', logging.WARNING, msg)
            for t in results.get('threats', []):
                fp = t.get('filepath', 'unknown')
                names = [x.get('name', '?') for x in t.get('threats', [])]
                self._log('threat', logging.WARNING, f"  Threat: {fp} → {', '.join(names)}")
        else:
            self._log('scan', logging.INFO, msg)

        if self.config.get('enable_json_logs', True):
            self._append_json_log('scan_results.json', {
                'event': 'scan_complete',
                'timestamp': datetime.now().isoformat(),
                'files_scanned': files,
                'threats_found': threats,
                'duration': duration,
            })

    def log_threat_detection(self, filepath: str, threat_info: Dict, action: str = 'detected'):
        msg = f"Threat {action}: {filepath}"
        self._log('threat', logging.WARNING, msg)

        if self.config.get('enable_json_logs', True):
            self._append_json_log('threat_detections.json', {
                'event': 'threat_detection',
                'timestamp': datetime.now().isoformat(),
                'filepath': filepath,
                'threat_info': threat_info,
                'action': action,
            })

    def log_quarantine_action(self, action: str, target: str, threat_name: str = None):
        msg = f"Quarantine {action}: {target} ({threat_name or 'Unknown'})"
        self._log('audit', logging.INFO, msg)

        if self.config.get('enable_json_logs', True):
            self._append_json_log('quarantine_actions.json', {
                'event': f'quarantine_{action}',
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'threat_name': threat_name,
            })

    def log_update(self, component: str, version: str, status: str, details: str = None):
        level = logging.INFO if status == 'success' else logging.ERROR
        msg = f"Update {status}: {component} → {version}"
        if details:
            msg += f" | {details}"
        self._log('audit', level, msg)

    def log_realtime_event(self, event_type: str, filepath: str, threat_info: Optional[Dict] = None):
        if threat_info:
            self._log('threat', logging.WARNING, f"Realtime {event_type}: {filepath} — threat detected")
        else:
            self._log('audit', logging.INFO, f"Realtime {event_type}: {filepath}")

    # ------------------------------------------------------------------
    # JSON log helpers
    # ------------------------------------------------------------------

    def _append_json_log(self, filename: str, entry: Dict):
        """Append an entry to a JSON-lines log file"""
        log_path = self.log_dir / filename
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Query & maintenance
    # ------------------------------------------------------------------

    def get_recent_logs(self, logger_name: str = 'main', limit: int = 100) -> List[Dict]:
        """Return recent log lines as dicts"""
        log_map = {
            'main': 'zwyrm.log',
            'threat': 'threats.log',
            'scan': 'scans.log',
            'audit': 'audit.log',
        }
        filename = log_map.get(logger_name, 'zwyrm.log')
        log_file = self.log_dir / filename

        entries = []
        if not log_file.exists():
            return entries

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[-limit:]

            for line in lines:
                parts = line.strip().split(' - ', 3)
                if len(parts) >= 4:
                    entries.append({
                        'timestamp': parts[0],
                        'name': parts[1],
                        'level': parts[2],
                        'message': parts[3],
                    })
        except Exception:
            pass

        return entries

    def get_statistics(self) -> Dict:
        """Return aggregated logging statistics"""
        by_level: Dict[str, int] = defaultdict(int)
        for counter in self.stats.values():
            for lvl, cnt in counter.items():
                by_level[lvl] += cnt

        return {
            'total': sum(by_level.values()),
            'by_logger': {n: dict(c) for n, c in self.stats.items()},
            'by_level': dict(by_level),
        }

    def clear_logs(self, logger_name: Optional[str] = None):
        """Truncate log files"""
        targets = []
        if logger_name:
            log_map = {
                'main': ['zwyrm.log'],
                'threat': ['threats.log'],
                'scan': ['scans.log'],
                'audit': ['audit.log'],
                'debug': ['debug.log'],
            }
            targets = [self.log_dir / f for f in log_map.get(logger_name, [])]
        else:
            targets = list(self.log_dir.glob('*.log')) + list(self.log_dir.glob('*.json'))

        for f in targets:
            try:
                open(f, 'w').close()
            except Exception:
                pass


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_instance: Optional[EnhancedZWYRMLogger] = None


def setup_logger(config_file: str = 'config.yaml') -> EnhancedZWYRMLogger:
    global _instance
    if _instance is None:
        _instance = EnhancedZWYRMLogger(config_file)
    return _instance


def get_logger() -> EnhancedZWYRMLogger:
    global _instance
    if _instance is None:
        _instance = EnhancedZWYRMLogger()
    return _instance
