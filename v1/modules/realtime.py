#!/usr/bin/env python3
# modules/realtime.py - Real-time filesystem monitoring via inotify

import os
import sys
import time
import json
import threading
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, List, Optional, Any

try:
    import pyinotify
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class EnhancedRealTimeMonitor:
    def __init__(self, scanner, quarantine_manager):
        self.scanner = scanner
        self.quarantine = quarantine_manager
        self.monitoring = False
        self.watch_manager = None
        self.notifier = None
        self.monitor_thread: Optional[threading.Thread] = None
        self.watch_descriptors: List[Any] = []

        self.config: Dict[str, Any] = {
            'monitor_paths': [
                os.path.expanduser('~/Downloads'),
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Documents'),
                '/tmp',
                '/var/tmp',
                os.path.expanduser('~/.local/share'),
            ],
            'exclude_paths': [
                '/proc', '/sys', '/dev', '/run',
                os.path.expanduser('~/.cache'),
                '/var/log',
            ],
            'monitor_extensions': {
                '.exe', '.dll', '.so', '.bat', '.cmd', '.vbs',
                '.js', '.ps1', '.sh', '.py', '.jar', '.class',
            },
            'scan_delay': 2,
            'max_file_size': 50 * 1024 * 1024,
            'alert_on_detection': True,
            'auto_quarantine': True,
            'quarantine_threshold': 'medium',
            'monitor_processes': False,
        }

        self.alert_queue: deque = deque(maxlen=200)
        self.stats: Dict[str, Any] = {
            'files_monitored': 0,
            'files_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'alerts_generated': 0,
            'start_time': None,
        }

        # Pending-scan queue to avoid race conditions on new files
        self._pending: deque = deque()
        self._pending_lock = threading.Lock()
        self._scan_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Event handler (inner class)
    # ------------------------------------------------------------------

    class _EventHandler:
        def __init__(self, monitor: 'EnhancedRealTimeMonitor'):
            self.monitor = monitor

        # inotify events
        def process_IN_CREATE(self, event):
            self._queue(event.pathname, 'CREATE')

        def process_IN_CLOSE_WRITE(self, event):
            self._queue(event.pathname, 'CLOSE_WRITE')

        def process_IN_MOVED_TO(self, event):
            self._queue(event.pathname, 'MOVED_TO')

        def process_IN_MODIFY(self, event):
            self._queue(event.pathname, 'MODIFY')

        def _queue(self, path: str, event_type: str):
            # Skip directories
            if not os.path.isfile(path):
                return
            # Skip excluded paths
            for excl in self.monitor.config['exclude_paths']:
                if path.startswith(excl):
                    return
            # Skip large files
            try:
                if os.path.getsize(path) > self.monitor.config['max_file_size']:
                    return
            except OSError:
                return
            # Extension filter
            ext = Path(path).suffix.lower()
            if ext and ext not in self.monitor.config['monitor_extensions']:
                return

            with self.monitor._pending_lock:
                self.monitor._pending.append((path, event_type, time.time()))

    # ------------------------------------------------------------------
    # Scan worker
    # ------------------------------------------------------------------

    def _scan_worker(self):
        """Background thread that processes the pending-scan deque"""
        while self.monitoring:
            item = None
            with self._pending_lock:
                if self._pending:
                    item = self._pending.popleft()

            if item is None:
                time.sleep(0.2)
                continue

            path, event_type, enqueued_at = item
            # Wait for file to be fully written
            wait = self.config['scan_delay'] - (time.time() - enqueued_at)
            if wait > 0:
                time.sleep(wait)

            if os.path.isfile(path):
                self._scan_and_respond(path, event_type)
                self.stats['files_scanned'] += 1

    # ------------------------------------------------------------------
    # Detection & response
    # ------------------------------------------------------------------

    def _scan_and_respond(self, filepath: str, event_type: str):
        """Scan a file and take action on detection"""
        try:
            result = self.scanner.scan_single_file(filepath)
            self.stats['files_monitored'] += 1

            if not result.get('clean', True):
                self.stats['threats_detected'] += 1
                self._log_detection(filepath, result, event_type)

                if self.config['alert_on_detection']:
                    self._emit_alert(filepath, result)

                if self.config['auto_quarantine']:
                    level = self._threat_level(result)
                    threshold_map = {'low': 1, 'medium': 2, 'high': 3}
                    if threshold_map.get(level, 0) >= threshold_map.get(
                            self.config['quarantine_threshold'], 2):
                        self._quarantine(filepath, result)

        except Exception as e:
            pass  # Don't let scan errors crash the monitor

    def _threat_level(self, scan_result: Dict) -> str:
        threats = scan_result.get('threats', [])
        if not threats:
            return 'low'
        severities = [t.get('severity', 'low') for t in threats]
        if 'high' in severities or any(t.get('type') == 'known_malware' for t in threats):
            return 'high'
        if 'medium' in severities:
            return 'medium'
        return 'low'

    def _quarantine(self, filepath: str, scan_result: Dict):
        threat_name = 'Unknown'
        threats = scan_result.get('threats', [])
        if threats:
            threat_name = threats[0].get('name', 'Unknown')

        qid = self.quarantine.quarantine_file(filepath, threat_name)
        if qid != -1:
            self.stats['files_quarantined'] += 1
            print(f"\n\033[91m[ZWYRM RT] Quarantined: {Path(filepath).name} → {threat_name}\033[0m")
            self._desktop_notify("ZWYRM Threat Quarantined",
                                  f"{Path(filepath).name}\nThreat: {threat_name}")

    def _emit_alert(self, filepath: str, scan_result: Dict):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'filepath': filepath,
            'filename': Path(filepath).name,
            'threats': scan_result.get('threats', []),
            'action': 'quarantined' if self.config['auto_quarantine'] else 'logged',
        }
        self.alert_queue.append(alert)
        self.stats['alerts_generated'] += 1

        print(f"\n\033[91m⚠ REAL-TIME THREAT ALERT ⚠\033[0m")
        print(f"  File: {filepath}")
        for t in scan_result.get('threats', []):
            print(f"  Threat: {t.get('name', 'Unknown')} [{t.get('severity', '?')}]")

        self._write_alert_log(alert)

    def _log_detection(self, filepath: str, scan_result: Dict, event_type: str):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'filepath': filepath,
            'threats': scan_result.get('threats', []),
        }
        self._write_alert_log(entry, filename='realtime_detections.json')

    def _write_alert_log(self, data: Dict, filename: str = 'alerts.json'):
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        try:
            with open(log_dir / filename, 'a') as f:
                f.write(json.dumps(data) + '\n')
        except Exception:
            pass

    def _desktop_notify(self, title: str, message: str):
        try:
            subprocess.run(
                ['notify-send', '-u', 'critical', title, message],
                timeout=3, capture_output=True
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Start / stop / status
    # ------------------------------------------------------------------

    def start(self) -> bool:
        if not INOTIFY_AVAILABLE:
            print("pyinotify is not installed. Install with: pip install pyinotify")
            print("Real-time protection unavailable.")
            return False

        if self.monitoring:
            print("Real-time protection already running.")
            return True

        self.watch_manager = pyinotify.WatchManager()
        handler = self._EventHandler(self)
        event_handler = pyinotify.ProcessEvent()
        event_handler.process_IN_CREATE     = handler.process_IN_CREATE
        event_handler.process_IN_CLOSE_WRITE = handler.process_IN_CLOSE_WRITE
        event_handler.process_IN_MOVED_TO   = handler.process_IN_MOVED_TO
        event_handler.process_IN_MODIFY     = handler.process_IN_MODIFY

        self.notifier = pyinotify.Notifier(self.watch_manager, event_handler)

        mask = (pyinotify.IN_CREATE | pyinotify.IN_CLOSE_WRITE |
                pyinotify.IN_MOVED_TO | pyinotify.IN_MODIFY)

        watched = 0
        for path in self.config['monitor_paths']:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                try:
                    wd = self.watch_manager.add_watch(expanded, mask, rec=True, auto_add=True)
                    self.watch_descriptors.append(wd)
                    watched += 1
                    print(f"  ✓ Monitoring: {expanded}")
                except Exception as e:
                    print(f"  ✗ Cannot watch {expanded}: {e}")

        if watched == 0:
            print("No paths could be monitored.")
            return False

        self.monitoring = True
        self.stats['start_time'] = datetime.now().isoformat()

        # inotify event loop
        self.monitor_thread = threading.Thread(target=self._inotify_loop, daemon=True)
        self.monitor_thread.start()

        # Scan worker
        self._scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self._scan_thread.start()

        print(f"\n✅ Real-time protection active ({watched} path(s) monitored)")
        return True

    def _inotify_loop(self):
        while self.monitoring:
            try:
                self.notifier.process_events()
                if self.notifier.check_events(timeout=500):
                    self.notifier.read_events()
            except Exception:
                time.sleep(1)

    def stop(self) -> bool:
        if not self.monitoring:
            return True

        self.monitoring = False

        if self.notifier:
            try:
                self.notifier.stop()
            except Exception:
                pass

        start = self.stats.get('start_time')
        if start:
            duration = datetime.now() - datetime.fromisoformat(start)
            print(f"\n📊 Real-time stats: duration={duration}, "
                  f"scanned={self.stats['files_scanned']}, "
                  f"threats={self.stats['threats_detected']}, "
                  f"quarantined={self.stats['files_quarantined']}")

        print("🛑 Real-time protection stopped.")
        return True

    def status(self) -> Dict:
        return {
            'monitoring': self.monitoring,
            'paths': len(self.config['monitor_paths']),
            'active_since': self.stats.get('start_time'),
            'statistics': dict(self.stats),
        }

    def add_path(self, path: str) -> bool:
        expanded = os.path.expanduser(path)
        if expanded not in self.config['monitor_paths'] and os.path.exists(expanded):
            self.config['monitor_paths'].append(expanded)
            if self.monitoring and self.watch_manager:
                mask = (pyinotify.IN_CREATE | pyinotify.IN_CLOSE_WRITE |
                        pyinotify.IN_MOVED_TO | pyinotify.IN_MODIFY)
                try:
                    self.watch_manager.add_watch(expanded, mask, rec=True, auto_add=True)
                except Exception:
                    pass
            return True
        return False

    def get_alerts(self, limit: int = 20) -> List[Dict]:
        alerts = list(self.alert_queue)
        return alerts[-limit:]


# Alias for backward compatibility
RealTimeMonitor = EnhancedRealTimeMonitor
