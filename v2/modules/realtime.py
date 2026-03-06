#!/usr/bin/env python3
# modules/realtime.py - Real-time filesystem monitoring (inotify-based)

import os, time, threading, queue
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable

try:
    import pyinotify; INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

try:
    import yaml; YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class EnhancedRealTimeMonitor:
    """Real-time filesystem monitor using inotify (Linux)."""

    def __init__(self, scanner=None, quarantine_manager=None, logger=None):
        self.scanner = scanner
        self.quarantine = quarantine_manager
        self.logger = logger
        self.monitoring = False
        self._pending: List = []
        self._pending_lock = threading.Lock()
        self._notifier = None
        self._watch_manager = None
        self._worker_thread = None
        self.scan_delay = 2  # seconds before scanning new files
        self.auto_quarantine = False
        self.monitor_paths: List[str] = []
        self.exclude_paths: List[str] = []
        self.monitor_extensions = {'.exe','.dll','.so','.bat','.sh','.py','.js','.php','.pl','.rb','.cmd','.vbs','.ps1'}
        self._load_config()

    def _load_config(self):
        base = Path.home() / '.zwyrm'
        cfg_path = base / 'config.yaml' if base.exists() else Path('config.yaml')
        if YAML_AVAILABLE and cfg_path.exists():
            try:
                with open(cfg_path) as f: cfg = yaml.safe_load(f) or {}
                rt = cfg.get('realtime', {})
                self.scan_delay = rt.get('scan_delay', 2)
                self.auto_quarantine = rt.get('action_on_detection','') == 'quarantine'
                self.monitor_paths = [os.path.expanduser(p) for p in rt.get('monitor_paths',[])]
                self.exclude_paths = [os.path.expanduser(p) for p in rt.get('exclude_paths',[])]
                exts = rt.get('monitor_extensions', [])
                if exts: self.monitor_extensions = set(exts)
            except: pass
        if not self.monitor_paths:
            self.monitor_paths = [os.path.expanduser('~/Downloads'), os.path.expanduser('~/Desktop'), '/tmp']

    def start(self, paths: Optional[List[str]] = None) -> bool:
        if self.monitoring:
            print("⚠ Real-time monitor already running."); return False
        if not INOTIFY_AVAILABLE:
            print("⚠ pyinotify not installed. Real-time monitoring unavailable.")
            print("  Install: pip install pyinotify"); return False
        if paths: self.monitor_paths = [os.path.expanduser(p) for p in paths]
        valid_paths = [p for p in self.monitor_paths if os.path.exists(p)]
        if not valid_paths:
            print("⚠ No valid paths to monitor."); return False
        try:
            self.monitoring = True
            self._worker_thread = threading.Thread(target=self._scan_worker, daemon=True)
            self._worker_thread.start()
            monitor_thread = threading.Thread(target=self._inotify_loop, args=(valid_paths,), daemon=True)
            monitor_thread.start()
            print(f"✓ Real-time monitor started on {len(valid_paths)} path(s):")
            for p in valid_paths: print(f"  • {p}")
            return True
        except Exception as e:
            self.monitoring = False; print(f"✗ Failed to start monitor: {e}"); return False

    def stop(self):
        self.monitoring = False
        if self._notifier:
            try: self._notifier.stop()
            except: pass
        print("✓ Real-time monitor stopped.")

    def status(self) -> Dict:
        return {'monitoring': self.monitoring, 'paths': self.monitor_paths, 'auto_quarantine': self.auto_quarantine, 'inotify_available': INOTIFY_AVAILABLE}

    def _inotify_loop(self, paths: List[str]):
        if not INOTIFY_AVAILABLE: return
        try:
            wm = pyinotify.WatchManager()
            handler = self._make_handler()
            notifier = pyinotify.Notifier(wm, handler, timeout=100)
            mask = pyinotify.IN_CLOSE_WRITE | pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO
            for p in paths:
                wm.add_watch(p, mask, rec=True, auto_add=True)
            self._notifier = notifier
            while self.monitoring:
                notifier.process_events()
                if notifier.check_events(): notifier.read_events()
            notifier.stop()
        except Exception as e:
            print(f"inotify error: {e}"); self.monitoring = False

    def _make_handler(self):
        monitor = self
        class Handler(pyinotify.ProcessEvent):
            def process_IN_CLOSE_WRITE(self, event): monitor._queue_file(event.pathname)
            def process_IN_CREATE(self, event): monitor._queue_file(event.pathname)
            def process_IN_MOVED_TO(self, event): monitor._queue_file(event.pathname)
        return Handler()

    def _queue_file(self, filepath: str):
        if not os.path.isfile(filepath): return
        ext = Path(filepath).suffix.lower()
        if ext not in self.monitor_extensions: return
        if any(filepath.startswith(ep) for ep in self.exclude_paths): return
        with self._pending_lock:
            self._pending.append((filepath, time.time()))

    def _scan_worker(self):
        while self.monitoring:
            time.sleep(0.5)
            to_scan = []
            with self._pending_lock:
                now = time.time()
                remaining = []
                for fp, ts in self._pending:
                    if now - ts >= self.scan_delay: to_scan.append(fp)
                    else: remaining.append((fp, ts))
                self._pending = remaining
            for fp in to_scan:
                self._scan_and_respond(fp)

    def _scan_and_respond(self, filepath: str):
        if not self.scanner: return
        try:
            result = self.scanner.scan_single_file(filepath)
            if not result.get('clean', True):
                print(f"\n\033[91m⚠ THREAT DETECTED: {filepath}\033[0m")
                for t in result.get('threats', []): print(f"   - {t.get('name','Unknown')}")
                if self.logger: self.logger.log_threat_detection(filepath, result.get('threats',[]), 'realtime_detected')
                if self.auto_quarantine and self.quarantine:
                    threat_name = result['threats'][0].get('name','Unknown') if result['threats'] else 'Unknown'
                    qid = self.quarantine.quarantine_file(filepath, threat_name)
                    if qid > 0:
                        print(f"   ✓ Quarantined (ID: {qid})")
                        if self.logger: self.logger.log_quarantine_action('quarantine', filepath, threat_name)
        except Exception as e:
            pass


# Backward-compatibility alias
RealTimeMonitor = EnhancedRealTimeMonitor
