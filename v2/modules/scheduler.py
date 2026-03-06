#!/usr/bin/env python3
# modules/scheduler.py - Periodic scan scheduling

import threading, time, os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Callable

try:
    import schedule; SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

try:
    import yaml; YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class ScanScheduler:
    def __init__(self, scanner=None, quarantine_manager=None, logger=None):
        self.scanner = scanner
        self.quarantine = quarantine_manager
        self.logger = logger
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._jobs = []
        self._load_config()

    def _load_config(self):
        base = Path.home() / '.zwyrm'
        cfg_path = base / 'config.yaml' if base.exists() else Path('config.yaml')
        self.sched_config = {'enabled': False, 'daily_scan': {'enabled': True, 'time': '02:00', 'type': 'quick'}, 'weekly_scan': {'enabled': True, 'day': 'sunday', 'time': '03:00', 'type': 'full'}}
        if YAML_AVAILABLE and cfg_path.exists():
            try:
                with open(cfg_path) as f: cfg = yaml.safe_load(f) or {}
                if 'scheduler' in cfg: self.sched_config.update(cfg['scheduler'])
            except: pass

    def start(self) -> bool:
        if self.running: print("⚠ Scheduler already running."); return False
        if not SCHEDULE_AVAILABLE:
            print("⚠ schedule not installed: pip install schedule"); return False
        self._setup_jobs()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print("✓ Scheduler started.")
        return True

    def stop(self):
        self.running = False
        if SCHEDULE_AVAILABLE: schedule.clear()
        print("✓ Scheduler stopped.")

    def status(self) -> Dict:
        if not SCHEDULE_AVAILABLE: return {'running': False, 'error': 'schedule not installed'}
        return {'running': self.running, 'jobs': len(self._jobs), 'next_run': str(schedule.next_run()) if self.running else None}

    def _setup_jobs(self):
        if not SCHEDULE_AVAILABLE: return
        schedule.clear()
        dc = self.sched_config.get('daily_scan', {})
        if dc.get('enabled', True):
            t = dc.get('time', '02:00')
            schedule.every().day.at(t).do(self._run_scan, scan_type=dc.get('type','quick'))
            print(f"  • Daily {dc.get('type','quick')} scan at {t}")
        wc = self.sched_config.get('weekly_scan', {})
        if wc.get('enabled', False):
            day = wc.get('day','sunday').lower(); t = wc.get('time','03:00')
            job = getattr(schedule.every(), day, None)
            if job: job.at(t).do(self._run_scan, scan_type=wc.get('type','full')); print(f"  • Weekly {wc.get('type','full')} scan on {day} at {t}")

    def _run_scan(self, scan_type: str = 'quick'):
        if not self.scanner:
            print("⚠ Scheduler: no scanner available."); return
        print(f"\n[Scheduler] Starting {scan_type} scan at {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        if self.logger: self.logger.log_scan_start(scan_type, 'scheduled')
        try:
            if scan_type == 'quick': results = self.scanner.quick_scan()
            elif scan_type == 'full': results = self.scanner.full_system_scan()
            else: results = self.scanner.quick_scan()
            if self.logger: self.logger.log_scan_result(results)
            print(f"[Scheduler] Scan done — files: {results.get('files_scanned',0)}, threats: {results.get('threats_found',0)}")
            if results.get('threats_found', 0) > 0 and self.quarantine:
                for t in results.get('threats', []):
                    fp = t.get('filepath','')
                    if fp and os.path.exists(fp):
                        threat_name = t.get('threats',['Unknown'])[0].get('name','Unknown') if t.get('threats') else 'Unknown'
                        self.quarantine.quarantine_file(fp, threat_name)
        except Exception as e:
            print(f"[Scheduler] Scan error: {e}")

    def _loop(self):
        while self.running:
            if SCHEDULE_AVAILABLE: schedule.run_pending()
            time.sleep(30)

    def run_now(self, scan_type: str = 'quick') -> Dict:
        """Manually trigger a scan immediately."""
        self._run_scan(scan_type)
        return {'triggered': True, 'scan_type': scan_type, 'time': datetime.now().isoformat()}


# Backward-compatibility alias
EnhancedScheduler = ScanScheduler
