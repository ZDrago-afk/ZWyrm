# cli/interface.py
import os, sys
from datetime import datetime
from typing import Dict, List, Optional

class ZWYRMCLI:
    def __init__(self):
        self.logo = """
        ╔══════════════════════════════════════╗
        ║      ███████╗██╗    ██╗██╗   ██╗     ║
        ║      ╚══███╔╝██║    ██║██║   ██║     ║
        ║        ███╔╝ ██║ █╗ ██║██║   ██║     ║
        ║       ███╔╝  ██║███╗██║╚██╗ ██╔╝     ║
        ║      ███████╗╚███╔███╔╝ ╚████╔╝      ║
        ║      ╚══════╝ ╚══╝╚══╝   ╚═══╝       ║
        ║                                      ║
        ║         A n t i V i r u s  v 2 . 0   ║
        ╚══════════════════════════════════════╝
        """

    def display_header(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print("\033[96m" + self.logo + "\033[0m")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

    def display_results(self, results: Dict):
        print("\n" + "=" * 60)
        print("\033[1mSCAN RESULTS\033[0m")
        print("=" * 60)
        if 'error' in results:
            print(f"\033[91mError: {results['error']}\033[0m"); return
        if 'details' in results:
            for d in results['details']: self._print_scan_summary(d)
        else: self._print_scan_summary(results)
        if results.get('threats_found', 0) > 0:
            print(f"\n\033[91mTHREATS FOUND ({results['threats_found']}):\033[0m")
            for i, t in enumerate(results.get('threats', []), 1):
                print(f"  {i}. {t.get('filename', 'Unknown')}")
                for th in t.get('threats', []): print(f"     - {th.get('name','Unknown')}")
                print(f"     Path: {t.get('filepath','Unknown')}")
        print("\n" + "=" * 60)

    def _print_scan_summary(self, r: Dict):
        files = r.get('files_scanned',0); threats = r.get('threats_found',0)
        if threats == 0: print(f"\033[92m✓ No threats found.\033[0m")
        else: print(f"\033[91m⚠ Found {threats} threats.\033[0m")
        print(f"Files scanned: {files}")
        print(f"Clean files: {r.get('clean_files', files - threats)}")
        if 'scan_start' in r and 'scan_end' in r:
            try:
                dur = (datetime.fromisoformat(r['scan_end']) - datetime.fromisoformat(r['scan_start'])).total_seconds()
                print(f"Duration: {dur:.1f} seconds")
            except: pass

    def display_quarantine(self, items: list):
        if not items: print("No files in quarantine."); return
        print(f"\nQuarantined files ({len(items)}):")
        print("-" * 80)
        print(f"{'ID':<4} {'Date':<20} {'Filename':<30} {'Original Path':<40}")
        print("-" * 80)
        for item in items:
            print(f"{item['id']:<4} {item['quarantine_date'][:19]:<20} {item['filename'][:28]:<30} {item['original_path'][:38]:<40}")

    def display_help(self):
        self.display_header()
        print("\n\033[1mZWYRM AntiVirus - Help\033[0m")
        print("=" * 60)
        print("\n\033[1mUsage:\033[0m zwyrm <command> [options]")
        print("\n\033[1mCommands:\033[0m")
        print("  \033[92minfo\033[0m                       Display ZWYRM information")
        print("  \033[92mscan <path>\033[0m                Scan directory or file")
        print("  \033[92mupdate\033[0m                     Update virus signatures")
        print("  \033[92mquarantine --list\033[0m          List quarantined files")
        print("  \033[92mquarantine --restore <id>\033[0m  Restore file")
        print("  \033[92mquarantine --remove <id>\033[0m   Permanently delete from quarantine")
        print("  \033[92mrealtime --start\033[0m           Start real-time protection")
        print("  \033[92mrealtime --stop\033[0m            Stop real-time protection")
        print("  \033[92mrealtime --status\033[0m          Check real-time status")
        print("\n\033[1mScan Options:\033[0m")
        print("  -q, --quick    Quick scan (common locations)")
        print("  -f, --full     Full system scan")
        print("  -r, --remove   Auto-quarantine detected threats")
        print("  -v, --verbose  Show detailed scan information")
        print("\n\033[1mExamples:\033[0m")
        print("  zwyrm scan ~/Downloads --quick")
        print("  zwyrm scan /home --full --remove")
        print("  zwyrm update")
        print("  zwyrm quarantine --list")
        print("\n" + "=" * 60)

    def display_info(self, info_data: Dict):
        self.display_header()
        print(f"""
\033[1mZWYRM AntiVirus v2.0 - Linux Edition\033[0m
====================================
\033[1mStatus:\033[0m           {info_data.get('status','Ready')}
\033[1mVersion:\033[0m          {info_data.get('version','2.0')}
\033[1mDatabase:\033[0m         {info_data.get('signatures',0)} signatures
\033[1mLast Update:\033[0m      {info_data.get('last_update','Never')}
\033[1mQuarantine:\033[0m       {info_data.get('quarantine_count',0)} files
\033[1mInstallation:\033[0m     {info_data.get('install_dir','~/.zwyrm')}

\033[1mFeatures:\033[0m
  • Signature-based detection  • Heuristic analysis
  • YARA rules scanning        • Real-time protection
  • Scheduled scans            • Quarantine management

Type 'zwyrm --help' for command reference.
        """)

    def display_progress(self, current: int, total: int, message: str = "Scanning"):
        bar_length = 40; pct = current/total if total > 0 else 0
        bar = '█' * int(bar_length*pct) + '░' * (bar_length - int(bar_length*pct))
        sys.stdout.write(f"\r{message}: [{bar}] {current}/{total} ({pct:.1%})"); sys.stdout.flush()
        if current >= total: print()

    def display_warning(self, msg: str): print(f"\033[93m⚠ {msg}\033[0m")
    def display_error(self, msg: str): print(f"\033[91m✗ {msg}\033[0m")
    def display_success(self, msg: str): print(f"\033[92m✓ {msg}\033[0m")

    def display_threat_details(self, threat_data: Dict):
        print("\n\033[91mTHREAT DETAILS\033[0m"); print("=" * 60)
        print(f"File:     {threat_data.get('filepath','Unknown')}")
        print(f"Type:     {threat_data.get('type','Unknown')}")
        print(f"Severity: {threat_data.get('severity','Unknown')}")
        print(f"Score:    {threat_data.get('score',0)}/100")
        if 'indicators' in threat_data:
            print("Indicators:")
            for ind in threat_data['indicators']: print(f"  • {ind}")
        print("=" * 60)

    def display_update_progress(self, current: int, total: int, source: str = ""):
        if total > 0: pct = (current/total)*100; print(f"\rUpdating... {current}/{total} ({pct:.1f}%) {source}", end="")
        else: print(f"\rUpdating... {source}", end="")
        if current >= total and total > 0: print()
