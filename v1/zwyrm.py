#!/usr/bin/env python3
# zwyrm.py - ZWYRM AntiVirus v2.0 — Main Entry Point

import os
import sys
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap: ensure modules can be found whether run from the project
# root or from ~/.zwyrm/
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# Also support running from ~/.zwyrm/
_USER_DIR = Path.home() / '.zwyrm'
if _USER_DIR.exists() and str(_USER_DIR) not in sys.path:
    sys.path.insert(0, str(_USER_DIR))


def _check_python():
    if sys.version_info < (3, 7):
        print("ZWYRM requires Python 3.7 or higher.")
        print(f"  Current: {sys.version}")
        sys.exit(1)


def _import_modules():
    """Import all ZWYRM modules with friendly error messages"""
    try:
        from core.scanner import ZWYRMScanner
        from core.quarantine import QuarantineManager
        from core.updater import SignatureUpdater
        from cli.interface import ZWYRMCLI
        from utils.config import load_config
        from utils.logger import setup_logger
        return ZWYRMScanner, QuarantineManager, SignatureUpdater, ZWYRMCLI, load_config, setup_logger
    except ImportError as e:
        print(f"\n✗ Import error: {e}")
        print("\nPossible fixes:")
        print("  1. Run ./install.sh first")
        print("  2. Run: pip install -r requirements.txt")
        print(f"  3. Make sure you are running from the ZWYRM directory")
        sys.exit(1)


class ZWYRM:
    def __init__(self):
        _check_python()
        ZWYRMScanner, QuarantineManager, SignatureUpdater, ZWYRMCLI, load_config, setup_logger = _import_modules()

        try:
            self.config = load_config()
        except Exception as e:
            print(f"Warning: config load failed ({e}). Using defaults.")
            from utils.config import ZWYRMConfig
            self.config = ZWYRMConfig()

        try:
            self.logger = setup_logger()
        except Exception as e:
            print(f"Warning: logger init failed ({e}).")
            self.logger = None

        try:
            self.scanner = ZWYRMScanner()
        except Exception as e:
            print(f"✗ Scanner init failed: {e}")
            sys.exit(1)

        try:
            quarantine_path = str(Path.home() / '.zwyrm' / 'quarantine')
            self.quarantine = QuarantineManager(quarantine_dir=quarantine_path)
        except Exception as e:
            print(f"Warning: Quarantine init failed ({e}). Using local quarantine/")
            self.quarantine = QuarantineManager()

        try:
            self.updater = SignatureUpdater()
        except Exception as e:
            print(f"Warning: Updater init failed ({e}).")
            self.updater = None

        self.cli = ZWYRMCLI()

    # ------------------------------------------------------------------
    # Argument parsing
    # ------------------------------------------------------------------

    def run(self):
        parser = argparse.ArgumentParser(
            prog='zwyrm',
            description='ZWYRM AntiVirus v2.0 — Linux Security Framework',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  zwyrm scan ~/Downloads          Scan a directory
  zwyrm scan -q ~/Downloads       Quick scan
  zwyrm scan -f /                 Full system scan
  zwyrm scan -r ~/Downloads       Scan and auto-quarantine threats
  zwyrm update                    Update virus signatures
  zwyrm quarantine --list         List quarantined files
  zwyrm realtime --start          Start real-time protection
"""
        )

        sub = parser.add_subparsers(dest='command')

        # scan
        sp = sub.add_parser('scan', help='Scan a file or directory')
        sp.add_argument('path', help='Path to scan')
        sp.add_argument('-q', '--quick',   action='store_true', help='Quick scan mode')
        sp.add_argument('-f', '--full',    action='store_true', help='Full system scan')
        sp.add_argument('-r', '--remove',  action='store_true', help='Auto-quarantine threats')
        sp.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

        # update
        up = sub.add_parser('update', help='Update signatures')
        up.add_argument('-f', '--force', action='store_true', help='Force update')

        # quarantine
        qp = sub.add_parser('quarantine', help='Manage quarantine')
        qg = qp.add_mutually_exclusive_group(required=True)
        qg.add_argument('--list',  action='store_true',  help='List quarantined files')
        qg.add_argument('--restore', type=int, metavar='ID', help='Restore item by ID')
        qg.add_argument('--remove',  type=int, metavar='ID', help='Delete item by ID')
        qg.add_argument('--clear',  action='store_true',  help='Delete all quarantine items')

        # realtime
        rp = sub.add_parser('realtime', help='Real-time protection')
        rg = rp.add_mutually_exclusive_group(required=True)
        rg.add_argument('--start',  action='store_true', help='Start monitoring')
        rg.add_argument('--stop',   action='store_true', help='Stop monitoring')
        rg.add_argument('--status', action='store_true', help='Check status')

        # info / help / version
        sub.add_parser('info',    help='Show ZWYRM information')
        sub.add_parser('help',    help='Show detailed help')
        sub.add_parser('version', help='Show version')

        args = parser.parse_args()

        if not args.command:
            self.cli.display_help()
            return

        try:
            dispatch = {
                'scan':       self._handle_scan,
                'update':     self._handle_update,
                'quarantine': self._handle_quarantine,
                'realtime':   self._handle_realtime,
                'info':       self._show_info,
                'help':       lambda _: self.cli.display_help(),
                'version':    self._show_version,
            }
            dispatch[args.command](args)

        except KeyboardInterrupt:
            print("\n\nOperation cancelled.")
            sys.exit(130)
        except Exception as e:
            self.cli.display_error(str(e))
            debug = self.config.get('zwyrm.debug_mode', False)
            if debug:
                import traceback
                traceback.print_exc()
            if self.logger:
                self.logger.log_error(str(e), 'main')
            sys.exit(1)

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def _handle_scan(self, args):
        self.cli.display_header()

        path = args.path
        if not os.path.exists(path):
            self.cli.display_error(f"Path not found: {path}")
            return

        print(f"Target : {path}")
        print("=" * 60)

        if args.quick:
            print("Mode   : Quick scan")
            results = self.scanner.quick_scan(path)
        elif args.full:
            print("Mode   : Full system scan")
            results = self.scanner.full_system_scan()
        else:
            print("Mode   : Directory scan")
            results = self.scanner.scan_directory(path)

        self.cli.display_results(results)

        # Auto-quarantine
        if args.remove and results.get('threats_found', 0) > 0:
            print("\n" + "=" * 60)
            print("Auto-quarantine:")
            for threat in results.get('threats', []):
                fp = threat.get('filepath')
                if fp and os.path.exists(fp):
                    tname = (threat.get('threats') or [{}])[0].get('name', 'Unknown')
                    qid = self.quarantine.quarantine_file(fp, tname)
                    if qid != -1:
                        self.cli.display_success(f"Quarantined: {os.path.basename(fp)} (ID #{qid})")
                    else:
                        self.cli.display_error(f"Failed to quarantine: {fp}")

        if self.logger:
            self.logger.log_scan_result(results)

    def _handle_update(self, args):
        self.cli.display_header()
        if not self.updater:
            self.cli.display_error("Updater module not available.")
            return

        print("Updating ZWYRM virus signatures …")
        print("=" * 60)

        success = self.updater.update_signatures(force=getattr(args, 'force', False))
        if success:
            count = self.updater.get_signature_count()
            self.cli.display_success(f"Signatures updated successfully! Total: {count:,}")
        else:
            self.cli.display_warning("No updates applied (already up to date, or network error).")

    def _handle_quarantine(self, args):
        if args.list:
            items = self.quarantine.list_quarantined()
            self.cli.display_quarantine(items)

        elif args.restore is not None:
            self.cli.display_header()
            print(f"Restoring item #{args.restore} …")
            if self.quarantine.restore(args.restore):
                self.cli.display_success(f"Item #{args.restore} restored.")
                if self.logger:
                    self.logger.log_quarantine_action('restore', f"#{args.restore}")
            else:
                self.cli.display_error(f"Could not restore item #{args.restore}.")

        elif args.remove is not None:
            self.cli.display_header()
            print(f"Permanently deleting item #{args.remove} …")
            if self.quarantine.delete(args.remove):
                self.cli.display_success(f"Item #{args.remove} deleted.")
                if self.logger:
                    self.logger.log_quarantine_action('delete', f"#{args.remove}")
            else:
                self.cli.display_error(f"Could not delete item #{args.remove}.")

        elif args.clear:
            self.cli.display_header()
            count = self.quarantine.count()
            if count == 0:
                print("Quarantine is already empty.")
                return
            confirm = input(f"Permanently delete {count} quarantined file(s)? [y/N]: ")
            if confirm.strip().lower() == 'y':
                deleted = self.quarantine.clear_all()
                self.cli.display_success(f"Deleted {deleted} file(s) from quarantine.")
            else:
                print("Cancelled.")

    def _handle_realtime(self, args):
        try:
            from modules.realtime import RealTimeMonitor
        except ImportError:
            self.cli.display_error("Real-time module not available.")
            print("Install pyinotify: pip install pyinotify")
            return

        rt = RealTimeMonitor(self.scanner, self.quarantine)

        if args.start:
            self.cli.display_header()
            print("Starting real-time protection …")
            if rt.start():
                self.cli.display_success("Real-time protection activated.")
                print("Press Ctrl+C to stop.")
                try:
                    import time
                    while rt.monitoring:
                        time.sleep(1)
                except KeyboardInterrupt:
                    rt.stop()
            else:
                self.cli.display_error("Failed to start real-time protection.")

        elif args.stop:
            self.cli.display_header()
            rt.stop()

        elif args.status:
            self.cli.display_header()
            status = rt.status()
            print("Real-time Protection Status")
            print("=" * 60)
            if status.get('monitoring'):
                self.cli.display_success("ACTIVE")
                print(f"  Since       : {status.get('active_since', 'Unknown')}")
                print(f"  Paths       : {status.get('paths', 0)}")
                stats = status.get('statistics', {})
                print(f"  Files scanned: {stats.get('files_scanned', 0)}")
                print(f"  Threats      : {stats.get('threats_detected', 0)}")
            else:
                self.cli.display_warning("INACTIVE")
                print("  Start with: zwyrm realtime --start")

    def _show_info(self, _args=None):
        sig_count = 0
        last_update = 'Never'
        if self.updater:
            try:
                sig_count = self.updater.get_signature_count()
                last_update = self.updater.get_last_update()
            except Exception:
                pass

        q_count = 0
        try:
            q_count = self.quarantine.count()
        except Exception:
            pass

        install_dir = str(self.updater.base_dir if self.updater else Path.home() / '.zwyrm')

        self.cli.display_info({
            'status': 'Ready',
            'version': '2.0',
            'signatures': sig_count,
            'last_update': last_update,
            'quarantine_count': q_count,
            'install_dir': install_dir,
            'config_file': str(self.config._config_file),
            'log_dir': str(Path(install_dir) / 'logs'),
        })

    def _show_version(self, _args=None):
        print("""
ZWYRM AntiVirus v2.0 — Linux Security Framework
================================================
Build    : 2026.03
License  : MIT Open Source
Author   : ZWYRM Security Team
Python   : """ + sys.version.split()[0])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    if os.geteuid() == 0:
        print("⚠  Running as root. User-mode installation is recommended.\n")

    try:
        app = ZWYRM()
        app.run()
    except KeyboardInterrupt:
        print("\nZWYRM terminated.")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
