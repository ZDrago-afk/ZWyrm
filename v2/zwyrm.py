#!/usr/bin/env python3
# zwyrm.py - ZWYRM AntiVirus v2.0 Main Entry Point

import sys, os, argparse
from pathlib import Path

# Bootstrap: add both project root and ~/.zwyrm to sys.path
_here = Path(__file__).resolve().parent
_user_base = Path.home() / '.zwyrm'
for _p in [str(_here), str(_user_base)]:
    if _p not in sys.path: sys.path.insert(0, _p)


def _load_modules():
    modules = {}
    try: from utils.config import ZWYRMConfig; modules['config'] = ZWYRMConfig
    except Exception as e: print(f"⚠ config load failed: {e}")
    try: from utils.logger import EnhancedZWYRMLogger; modules['logger'] = EnhancedZWYRMLogger
    except Exception as e: print(f"⚠ logger load failed: {e}")
    try: from core.scanner import EnhancedZWYRMScanner; modules['scanner'] = EnhancedZWYRMScanner
    except Exception as e: print(f"⚠ scanner load failed: {e}")
    try: from core.quarantine import QuarantineManager; modules['quarantine'] = QuarantineManager
    except Exception as e: print(f"⚠ quarantine load failed: {e}")
    try: from core.updater import EnhancedSignatureUpdater; modules['updater'] = EnhancedSignatureUpdater
    except Exception as e: print(f"⚠ updater load failed: {e}")
    try: from core.detector import AdvancedAIDetector; modules['detector'] = AdvancedAIDetector
    except Exception as e: print(f"⚠ detector load failed: {e}")
    try: from cli.interface import ZWYRMCLI; modules['cli'] = ZWYRMCLI
    except Exception as e: print(f"⚠ CLI load failed: {e}")
    try: from modules.realtime import EnhancedRealTimeMonitor; modules['realtime'] = EnhancedRealTimeMonitor
    except Exception as e: print(f"⚠ realtime load failed: {e}")
    try: from modules.scheduler import ScanScheduler; modules['scheduler'] = ScanScheduler
    except Exception as e: print(f"⚠ scheduler load failed: {e}")
    return modules


class ZWYRMApp:
    def __init__(self):
        self.mods = _load_modules()
        self.config = self.mods['config']() if 'config' in self.mods else None
        self.logger = self.mods['logger']() if 'logger' in self.mods else None
        self.scanner = self.mods['scanner']() if 'scanner' in self.mods else None
        self.quarantine = self.mods['quarantine']() if 'quarantine' in self.mods else None
        self.updater = self.mods['updater']() if 'updater' in self.mods else None
        self.cli = self.mods['cli']() if 'cli' in self.mods else None
        self.realtime_monitor = None  # Created on demand
        self.scheduler = None         # Created on demand
        self.debug = self.config.get('zwyrm.debug_mode', False) if self.config else False

    # ------------------------------------------------------------------ info
    def cmd_info(self):
        info = {
            'status': 'Ready' if self.scanner else 'Degraded',
            'version': '2.0',
            'signatures': self.updater.get_signature_count() if self.updater else 0,
            'last_update': self.updater.get_last_update() if self.updater else 'Never',
            'quarantine_count': self.quarantine.count() if self.quarantine else 0,
            'install_dir': str(_user_base if _user_base.exists() else _here),
            'config_file': str(self.config.config_file) if self.config else 'N/A',
            'log_dir': str(_user_base / 'logs' if _user_base.exists() else 'logs'),
        }
        if self.cli: self.cli.display_info(info)
        else: print(info)

    # ------------------------------------------------------------------ scan
    def cmd_scan(self, path: str, quick: bool = False, full: bool = False,
                 auto_remove: bool = False, verbose: bool = False):
        if not self.scanner:
            print("✗ Scanner not available."); return
        if self.cli: self.cli.display_header()
        if self.logger: self.logger.log_scan_start('scan', path)
        print(f"Scanning: {path}")
        if quick: results = self.scanner.quick_scan()
        elif full: results = self.scanner.full_system_scan()
        elif os.path.isfile(path): results = self.scanner.scan_single_file(path)
        else: results = self.scanner.scan_directory(path, recursive=True)
        if self.cli: self.cli.display_results(results)
        if self.logger: self.logger.log_scan_result(results)
        if auto_remove and results.get('threats_found', 0) > 0 and self.quarantine:
            for threat in results.get('threats', []):
                fp = threat.get('filepath', '')
                if fp and os.path.exists(fp):
                    threat_name = threat.get('threats', [{'name':'Unknown'}])[0].get('name','Unknown')
                    qid = self.quarantine.quarantine_file(fp, threat_name)
                    if qid > 0:
                        if self.cli: self.cli.display_success(f"Quarantined: {os.path.basename(fp)} (ID: {qid})")
                        if self.logger: self.logger.log_quarantine_action('quarantine', fp, threat_name)

    # ------------------------------------------------------------------ update
    def cmd_update(self, force: bool = False):
        if not self.updater:
            print("✗ Updater not available."); return
        print("Updating virus signatures...")
        results = self.updater.update_signatures(force=force)
        if results.get('success'):
            msg = results.get('message','Done')
            if self.cli: self.cli.display_success(msg)
            else: print(f"✓ {msg}")
        else:
            msg = results.get('message','Update failed')
            if self.cli: self.cli.display_error(msg)
            else: print(f"✗ {msg}")
            if results.get('errors'):
                for e in results['errors']: print(f"  - {e.get('source')}: {e.get('error')}")

    # ------------------------------------------------------------------ quarantine
    def cmd_quarantine(self, action: str, item_id: int = None):
        if not self.quarantine:
            print("✗ Quarantine not available."); return
        if action == 'list':
            items = self.quarantine.list_quarantined()
            if self.cli: self.cli.display_quarantine(items)
            else:
                if not items: print("No files in quarantine.")
                else:
                    for i in items: print(f"[{i['id']}] {i['filename']} — {i['quarantine_date'][:19]}")
        elif action == 'restore' and item_id is not None:
            if self.quarantine.restore(item_id):
                msg = f"Restored item {item_id}"
                if self.cli: self.cli.display_success(msg)
                else: print(f"✓ {msg}")
                if self.logger: self.logger.log_quarantine_action('restore', str(item_id))
            else:
                if self.cli: self.cli.display_error(f"Could not restore item {item_id}")
                else: print(f"✗ Could not restore item {item_id}")
        elif action == 'remove' and item_id is not None:
            if self.quarantine.delete(item_id):
                msg = f"Deleted item {item_id}"
                if self.cli: self.cli.display_success(msg)
                else: print(f"✓ {msg}")
            else:
                if self.cli: self.cli.display_error(f"Could not delete item {item_id}")
        elif action == 'clear':
            n = self.quarantine.clear_all()
            msg = f"Cleared {n} quarantined files"
            if self.cli: self.cli.display_success(msg)
            else: print(f"✓ {msg}")
        else:
            print("Quarantine actions: --list | --restore <id> | --remove <id> | --clear")

    # ------------------------------------------------------------------ realtime
    def cmd_realtime(self, action: str, paths=None):
        if action == 'start':
            if not self.realtime_monitor:
                if 'realtime' not in self.mods: print("✗ Real-time module unavailable."); return
                self.realtime_monitor = self.mods['realtime'](
                    scanner=self.scanner, quarantine_manager=self.quarantine, logger=self.logger)
            if self.realtime_monitor.start(paths):
                print("Real-time protection active. Press Ctrl+C to stop.")
                try:
                    import time
                    while self.realtime_monitor.monitoring: time.sleep(1)
                except KeyboardInterrupt:
                    self.realtime_monitor.stop()
            else:
                print("✗ Could not start real-time monitor.")
        elif action == 'stop':
            if self.realtime_monitor: self.realtime_monitor.stop()
            else: print("Real-time monitor not running.")
        elif action == 'status':
            if self.realtime_monitor:
                s = self.realtime_monitor.status()
                print(f"Real-time: {'ACTIVE' if s['monitoring'] else 'STOPPED'}")
                print(f"Paths: {', '.join(s['paths'])}")
                print(f"Auto-quarantine: {s['auto_quarantine']}")
                print(f"inotify available: {s['inotify_available']}")
            else: print("Real-time monitor not started.")

    # ------------------------------------------------------------------ scheduler
    def cmd_scheduler(self, action: str):
        if action == 'start':
            if not self.scheduler:
                if 'scheduler' not in self.mods: print("✗ Scheduler module unavailable."); return
                self.scheduler = self.mods['scheduler'](
                    scanner=self.scanner, quarantine_manager=self.quarantine, logger=self.logger)
            self.scheduler.start()
        elif action == 'stop':
            if self.scheduler: self.scheduler.stop()
            else: print("Scheduler not running.")
        elif action == 'status':
            if self.scheduler:
                s = self.scheduler.status()
                print(f"Scheduler: {'RUNNING' if s['running'] else 'STOPPED'}, jobs: {s.get('jobs',0)}")
            else: print("Scheduler not started.")


# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog='zwyrm', description='ZWYRM AntiVirus v2.0')
    sub = p.add_subparsers(dest='command')
    sub.add_parser('info', help='Show ZWYRM information')
    scan_p = sub.add_parser('scan', help='Scan a file or directory')
    scan_p.add_argument('path', nargs='?', default='.', help='Path to scan')
    scan_p.add_argument('-q','--quick', action='store_true', help='Quick scan')
    scan_p.add_argument('-f','--full', action='store_true', help='Full system scan')
    scan_p.add_argument('-r','--remove', action='store_true', help='Auto-quarantine threats')
    scan_p.add_argument('-v','--verbose', action='store_true', help='Verbose output')
    update_p = sub.add_parser('update', help='Update virus signatures')
    update_p.add_argument('--force', action='store_true', help='Force update')
    q_p = sub.add_parser('quarantine', help='Manage quarantine')
    q_group = q_p.add_mutually_exclusive_group()
    q_group.add_argument('--list', action='store_true')
    q_group.add_argument('--restore', type=int, metavar='ID')
    q_group.add_argument('--remove', type=int, metavar='ID')
    q_group.add_argument('--clear', action='store_true')
    rt_p = sub.add_parser('realtime', help='Real-time protection')
    rt_p.add_argument('action', choices=['start','stop','status'], nargs='?', default='status')
    rt_p.add_argument('--paths', nargs='+', help='Paths to monitor')
    sched_p = sub.add_parser('scheduler', help='Scan scheduler')
    sched_p.add_argument('action', choices=['start','stop','status'], nargs='?', default='status')
    p.add_argument('--version', action='version', version='ZWYRM AntiVirus v2.0')
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    app = ZWYRMApp()

    cmd = args.command
    if cmd == 'info' or cmd is None:
        app.cmd_info()
    elif cmd == 'scan':
        app.cmd_scan(args.path, quick=args.quick, full=args.full, auto_remove=args.remove, verbose=args.verbose)
    elif cmd == 'update':
        app.cmd_update(force=args.force)
    elif cmd == 'quarantine':
        if args.list: app.cmd_quarantine('list')
        elif args.restore is not None: app.cmd_quarantine('restore', args.restore)
        elif args.remove is not None: app.cmd_quarantine('remove', args.remove)
        elif args.clear: app.cmd_quarantine('clear')
        else: app.cmd_quarantine('list')
    elif cmd == 'realtime':
        app.cmd_realtime(args.action, paths=args.paths if hasattr(args,'paths') else None)
    elif cmd == 'scheduler':
        app.cmd_scheduler(args.action)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
