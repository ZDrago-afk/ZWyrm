#!/usr/bin/env python3
# modules/scheduler.py - Scheduled scan execution

import time
import json
import threading
import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

try:
    import schedule as schedule_lib
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False


class ScanScheduler:
    def __init__(self, scanner):
        self.scanner = scanner
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None

        db_dir = Path('database')
        db_dir.mkdir(exist_ok=True)
        self.schedule_file = db_dir / 'schedule.json'
        self.log_dir = Path('logs')
        self.log_dir.mkdir(exist_ok=True)

        self.scheduled_scans: Dict[str, Dict] = {}
        self._load_schedule()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_schedule(self):
        if self.schedule_file.exists():
            try:
                with open(self.schedule_file, 'r') as f:
                    self.scheduled_scans = json.load(f)
            except Exception:
                self.scheduled_scans = {}

    def _save_schedule(self):
        try:
            with open(self.schedule_file, 'w') as f:
                json.dump(self.scheduled_scans, f, indent=2)
        except Exception as e:
            print(f"Scheduler: could not save schedule: {e}")

    # ------------------------------------------------------------------
    # Schedule management
    # ------------------------------------------------------------------

    def add_daily_scan(self, scan_name: str, time_str: str, path: str,
                       scan_type: str = 'quick') -> str:
        job_id = f"daily_{scan_name}_{time_str.replace(':', '')}"
        self.scheduled_scans[job_id] = {
            'name': scan_name,
            'type': 'daily',
            'time': time_str,
            'path': path,
            'scan_type': scan_type,
            'enabled': True,
            'last_run': None,
        }
        self._save_schedule()
        self._rebuild_schedule()
        print(f"Added daily scan '{scan_name}' at {time_str}")
        return job_id

    def add_weekly_scan(self, scan_name: str, day_of_week: str, time_str: str,
                        path: str, scan_type: str = 'full') -> str:
        job_id = f"weekly_{scan_name}_{day_of_week}_{time_str.replace(':', '')}"
        self.scheduled_scans[job_id] = {
            'name': scan_name,
            'type': 'weekly',
            'day': day_of_week.lower(),
            'time': time_str,
            'path': path,
            'scan_type': scan_type,
            'enabled': True,
            'last_run': None,
        }
        self._save_schedule()
        self._rebuild_schedule()
        print(f"Added weekly scan '{scan_name}' on {day_of_week} at {time_str}")
        return job_id

    def remove_scan(self, job_id: str) -> bool:
        if job_id in self.scheduled_scans:
            del self.scheduled_scans[job_id]
            self._save_schedule()
            self._rebuild_schedule()
            print(f"Removed scan: {job_id}")
            return True
        return False

    def enable_scan(self, job_id: str) -> bool:
        if job_id in self.scheduled_scans:
            self.scheduled_scans[job_id]['enabled'] = True
            self._save_schedule()
            self._rebuild_schedule()
            return True
        return False

    def disable_scan(self, job_id: str) -> bool:
        if job_id in self.scheduled_scans:
            self.scheduled_scans[job_id]['enabled'] = False
            self._save_schedule()
            self._rebuild_schedule()
            return True
        return False

    # ------------------------------------------------------------------
    # Schedule engine
    # ------------------------------------------------------------------

    def _rebuild_schedule(self):
        """Rebuild the schedule library's job list"""
        if not SCHEDULE_AVAILABLE:
            return

        schedule_lib.clear()

        for job_id, job in self.scheduled_scans.items():
            if not job.get('enabled', True):
                continue
            try:
                if job['type'] == 'daily':
                    schedule_lib.every().day.at(job['time']).do(
                        self._run_job, job_id).tag(job_id)

                elif job['type'] == 'weekly':
                    day_method = getattr(schedule_lib.every(), job['day'], None)
                    if day_method:
                        day_method.at(job['time']).do(
                            self._run_job, job_id).tag(job_id)
            except Exception as e:
                print(f"Scheduler: could not schedule '{job_id}': {e}")

    def _run_job(self, job_id: str):
        job = self.scheduled_scans.get(job_id)
        if not job:
            return

        print(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] Running scheduled scan: {job['name']}")
        job['last_run'] = datetime.now().isoformat()
        self._save_schedule()

        try:
            scan_type = job.get('scan_type', 'quick')
            path = job.get('path', os.path.expanduser('~'))

            if scan_type == 'quick':
                results = self.scanner.quick_scan(path)
            elif scan_type == 'full':
                results = self.scanner.full_system_scan()
            else:
                results = self.scanner.scan_directory(path)

            self._log_results(job_id, job['name'], results)

            threats = results.get('threats_found', 0)
            if threats > 0:
                self._notify(job['name'], threats)

        except Exception as e:
            print(f"Scheduled scan '{job['name']}' failed: {e}")

    # ------------------------------------------------------------------
    # Logging & notifications
    # ------------------------------------------------------------------

    def _log_results(self, job_id: str, job_name: str, results: Dict):
        log_file = self.log_dir / f"schedule_{job_id}.log"
        entry = {
            'job_id': job_id,
            'job_name': job_name,
            'timestamp': datetime.now().isoformat(),
            'files_scanned': results.get('files_scanned', 0),
            'threats_found': results.get('threats_found', 0),
            'duration': results.get('duration', 0),
        }
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass

        print(f"  Files: {entry['files_scanned']}  Threats: {entry['threats_found']}  "
              f"Duration: {entry['duration']:.1f}s")

    def _notify(self, scan_name: str, threat_count: int):
        print(f"\n⚠ [{scan_name}] {threat_count} threat(s) detected!")
        try:
            subprocess.run(
                ['notify-send', 'ZWYRM Scheduled Scan',
                 f"{scan_name}: {threat_count} threat(s) found"],
                timeout=3, capture_output=True
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Daemon control
    # ------------------------------------------------------------------

    def start_scheduler(self):
        if not SCHEDULE_AVAILABLE:
            print("'schedule' package not installed. Install with: pip install schedule")
            return

        if self.running:
            print("Scheduler already running.")
            return

        self.running = True
        self._rebuild_schedule()

        def _loop():
            while self.running:
                schedule_lib.run_pending()
                time.sleep(30)  # Check every 30 seconds

        self.scheduler_thread = threading.Thread(target=_loop, daemon=True)
        self.scheduler_thread.start()

        enabled_count = sum(1 for j in self.scheduled_scans.values() if j.get('enabled', True))
        print(f"Scheduler started ({enabled_count} enabled job(s)).")

    def stop_scheduler(self):
        self.running = False
        if SCHEDULE_AVAILABLE:
            schedule_lib.clear()
        print("Scheduler stopped.")

    def list_scans(self):
        if not self.scheduled_scans:
            print("No scheduled scans configured.")
            return

        print("\n" + "=" * 70)
        print(f"{'ID':<35} {'Type':<10} {'Time':<8} {'Last Run':<22} {'Status'}")
        print("=" * 70)
        for job_id, job in self.scheduled_scans.items():
            status = "✓ enabled" if job.get('enabled', True) else "✗ disabled"
            last = job.get('last_run', 'Never')
            if last and last != 'Never':
                try:
                    last = datetime.fromisoformat(last).strftime('%Y-%m-%d %H:%M')
                except Exception:
                    pass
            sched = job.get('time', '?')
            if job.get('type') == 'weekly':
                sched = f"{job.get('day', '?')} {sched}"
            print(f"{job_id[:33]:<35} {job['type']:<10} {sched:<8} {str(last):<22} {status}")
        print()
