#!/usr/bin/env python3
# cli/interface.py - CLI presentation layer

import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any


class ZWYRMCLI:
    LOGO = """
        ╔══════════════════════════════════════════╗
        ║   ███████╗██╗    ██╗██╗   ██╗██████╗   ║
        ║   ╚══███╔╝██║    ██║╚██╗ ██╔╝██╔══██╗  ║
        ║     ███╔╝ ██║ █╗ ██║ ╚████╔╝ ██████╔╝  ║
        ║    ███╔╝  ██║███╗██║  ╚██╔╝  ██╔══██╗  ║
        ║   ███████╗╚███╔███╔╝   ██║   ██║  ██║  ║
        ║   ╚══════╝ ╚══╝╚══╝    ╚═╝   ╚═╝  ╚═╝  ║
        ║           A n t i V i r u s  v 2 . 0   ║
        ╚══════════════════════════════════════════╝"""

    # ANSI helpers
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

    def _c(self, text: str, color: str) -> str:
        return f"{color}{text}{self.RESET}"

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def display_header(self):
        if os.name == 'posix':
            os.system('clear')
        else:
            os.system('cls')
        print(self._c(self.LOGO, self.CYAN))
        print(f"  Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

    # ------------------------------------------------------------------
    # Scan results
    # ------------------------------------------------------------------

    def display_results(self, results: Dict):
        print("\n" + "=" * 60)
        print(self._c("SCAN RESULTS", self.BOLD))
        print("=" * 60)

        if 'error' in results:
            self.display_error(f"Scan error: {results['error']}")
            return

        # Quick-scan returns nested details
        if 'details' in results:
            for detail in results['details']:
                self._print_scan_summary(detail)
        else:
            self._print_scan_summary(results)

        threats = results.get('threats', [])
        if threats:
            print(f"\n{self._c(f'THREATS FOUND ({len(threats)}):', self.RED)}")
            for i, threat in enumerate(threats, 1):
                fp = threat.get('filepath', 'Unknown')
                filename = threat.get('filename', os.path.basename(fp))
                print(f"  {i}. {self._c(filename, self.RED)}")
                for t in threat.get('threats', []):
                    name = t.get('name', 'Unknown')
                    sev  = t.get('severity', '?')
                    ttype = t.get('type', '?')
                    print(f"     → {name}  [{ttype}] [{sev}]")
                print(f"     Path: {fp}")

        print("\n" + "=" * 60)

    def _print_scan_summary(self, results: Dict):
        files   = results.get('files_scanned', 0)
        threats = results.get('threats_found', 0)
        skipped = results.get('skipped_files', 0)
        errors  = results.get('errors', 0)
        mode    = results.get('scan_mode', 'scan')

        if threats == 0:
            print(self._c(f"✓ {mode.capitalize()} complete — no threats found.", self.GREEN))
        else:
            print(self._c(f"⚠ {mode.capitalize()} complete — {threats} threat(s) found!", self.RED))

        print(f"  Files scanned : {files}")
        print(f"  Clean files   : {results.get('clean_files', files - threats)}")
        if skipped:
            print(f"  Skipped       : {skipped}")
        if errors:
            print(f"  Errors        : {errors}")

        duration = results.get('duration')
        if duration is not None:
            print(f"  Duration      : {duration:.1f}s")
        elif 'scan_start' in results and 'scan_end' in results:
            try:
                start = datetime.fromisoformat(results['scan_start'])
                end   = datetime.fromisoformat(results['scan_end'])
                secs  = (end - start).total_seconds()
                print(f"  Duration      : {secs:.1f}s")
            except Exception:
                pass

        perf = results.get('performance', {})
        fps = perf.get('files_per_second', 0)
        if fps:
            print(f"  Speed         : {fps:.0f} files/s")

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------

    def display_quarantine(self, items: List[Dict]):
        if not items:
            print("Quarantine is empty.")
            return

        print(f"\nQuarantined files ({len(items)}):")
        print("-" * 100)
        print(f"{'ID':<5} {'Date':<22} {'Filename':<35} {'Threat':<25} {'Size':>8}")
        print("-" * 100)

        for item in items:
            qdate = item.get('quarantine_date', '')[:19]
            fname = item.get('filename', 'unknown')[:33]
            threat = item.get('threat_name', 'Unknown')[:23]
            size   = item.get('size', 0)
            size_s = self._human_size(size)
            print(f"{item.get('id', '?'):<5} {qdate:<22} {fname:<35} {threat:<25} {size_s:>8}")

        total = sum(i.get('size', 0) for i in items)
        print("-" * 100)
        print(f"Total: {len(items)} file(s), {self._human_size(total)}")

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size_bytes < 1024:
                return f"{size_bytes:.0f} {unit}"
            size_bytes //= 1024
        return f"{size_bytes:.0f} TB"

    # ------------------------------------------------------------------
    # Info
    # ------------------------------------------------------------------

    def display_info(self, info: Dict):
        self.display_header()
        sig_count = info.get('signatures', 0)
        if isinstance(sig_count, dict):
            # Breakdown dict
            sig_str = (f"{sig_count.get('md5', 0)} MD5 / "
                       f"{sig_count.get('sha256', 0)} SHA256 / "
                       f"{sig_count.get('patterns', 0)} patterns")
        else:
            sig_str = str(sig_count)

        print(f"""
{self._c('ZWYRM AntiVirus v2.0', self.BOLD)}
{'=' * 40}

  {self._c('Status:', self.BOLD)}       {info.get('status', 'Ready')}
  {self._c('Version:', self.BOLD)}      {info.get('version', '2.0')}
  {self._c('Signatures:', self.BOLD)}   {sig_str}
  {self._c('Last Update:', self.BOLD)}  {info.get('last_update', 'Never')}
  {self._c('Quarantine:', self.BOLD)}   {info.get('quarantine_count', 0)} file(s)
  {self._c('License:', self.BOLD)}      MIT Open Source

  {self._c('Install Dir:', self.BOLD)}  {info.get('install_dir', '~/.zwyrm')}
  {self._c('Config:', self.BOLD)}       {info.get('config_file', 'config.yaml')}
  {self._c('Logs:', self.BOLD)}         {info.get('log_dir', 'logs/')}

  {self._c('Detection Modules:', self.BOLD)}
    • Signature-based (MD5 / SHA256)
    • YARA rule matching
    • Heuristic analysis (entropy, packing, strings)
    • Behavioral pattern detection
    • PE structure analysis

Type 'zwyrm --help' for usage.
""")

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def display_help(self):
        self.display_header()
        print(f"""
{self._c('Usage:', self.BOLD)}
  zwyrm <command> [options]

{self._c('Commands:', self.BOLD)}
  {self._c('info', self.GREEN)}                         Show ZWYRM status
  {self._c('scan <path>', self.GREEN)}                  Scan file or directory
  {self._c('scan -q <path>', self.GREEN)}               Quick scan (common locations)
  {self._c('scan -f /', self.GREEN)}                    Full system scan
  {self._c('update [-f]', self.GREEN)}                  Download latest signatures
  {self._c('quarantine --list', self.GREEN)}            List quarantined files
  {self._c('quarantine --restore <id>', self.GREEN)}    Restore from quarantine
  {self._c('quarantine --remove <id>', self.GREEN)}     Permanently delete quarantine item
  {self._c('quarantine --clear', self.GREEN)}           Delete all quarantine items
  {self._c('realtime --start', self.GREEN)}             Start real-time protection
  {self._c('realtime --stop', self.GREEN)}              Stop real-time protection
  {self._c('realtime --status', self.GREEN)}            Check monitoring status
  {self._c('version', self.GREEN)}                      Show version

{self._c('Scan Flags:', self.BOLD)}
  -q, --quick      Quick scan (Downloads, Desktop, /tmp …)
  -f, --full       Full system scan
  -r, --remove     Auto-quarantine detected threats
  -v, --verbose    Detailed output

{self._c('Examples:', self.BOLD)}
  zwyrm scan ~/Downloads -r
  zwyrm scan /home --full
  zwyrm update
  zwyrm quarantine --list
  zwyrm realtime --start

{self._c('Config:', self.BOLD)}
  Edit ~/.zwyrm/config.yaml to customise settings.
""")

    # ------------------------------------------------------------------
    # Progress
    # ------------------------------------------------------------------

    def display_progress(self, current: int, total: int, label: str = 'Scanning'):
        if total <= 0:
            return
        pct = current / total
        filled = int(40 * pct)
        bar = '█' * filled + '░' * (40 - filled)
        sys.stdout.write(f"\r{label}: [{bar}] {current}/{total} ({pct:.1%})")
        sys.stdout.flush()
        if current >= total:
            print()

    # ------------------------------------------------------------------
    # Status messages
    # ------------------------------------------------------------------

    def display_success(self, msg: str):
        print(self._c(f"✓ {msg}", self.GREEN))

    def display_warning(self, msg: str):
        print(self._c(f"⚠ {msg}", self.YELLOW))

    def display_error(self, msg: str):
        print(self._c(f"✗ {msg}", self.RED))

    def display_threat_details(self, threat: Dict):
        print(f"\n{self._c('THREAT DETAILS', self.RED)}")
        print("=" * 60)
        print(f"  File    : {threat.get('filepath', 'Unknown')}")
        print(f"  Type    : {threat.get('type', 'Unknown')}")
        print(f"  Severity: {threat.get('severity', 'Unknown')}")
        print(f"  Score   : {threat.get('score', 0)}/100")
        indicators = threat.get('indicators', [])
        if indicators:
            print("\n  Indicators:")
            for ind in indicators:
                print(f"    • {ind}")
        print("=" * 60)
