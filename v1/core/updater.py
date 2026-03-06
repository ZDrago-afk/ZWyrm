#!/usr/bin/env python3
# core/updater.py - Multi-source signature updater with full implementation

import json
import hashlib
import time
import os
import threading
import concurrent.futures
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    import sqlite3
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class EnhancedSignatureUpdater:
    def __init__(self):
        # Resolve paths relative to install dir or cwd
        base = self._find_base_dir()
        self.base_dir = base
        self.db_dir = base / 'database'
        self.db_dir.mkdir(parents=True, exist_ok=True)

        self.signatures_db = self.db_dir / 'signatures.db'
        self.signatures_sqlite = self.db_dir / 'signatures.sqlite'
        self.last_update_file = self.db_dir / 'last_update.json'
        self.yara_dir = self.db_dir / 'yara_rules'
        self.yara_dir.mkdir(exist_ok=True)

        # Update sources
        self.update_sources = [
            {
                'name': 'MalwareBazaar',
                'url': 'https://bazaar.abuse.ch/export/txt/md5/full/',
                'type': 'md5',
                'enabled': True,
                'priority': 1
            },
            {
                'name': 'VirusShare',
                'url': 'https://virusshare.com/hashfiles/VirusShare_00000.md5',
                'type': 'md5',
                'enabled': True,
                'priority': 2
            },
            {
                'name': 'TheZoo',
                'url': 'https://raw.githubusercontent.com/ytisf/theZoo/master/misc/vx-heaven/vxdb.txt',
                'type': 'vxdb',
                'enabled': True,
                'priority': 3
            },
        ]

        self.config = {
            'auto_update': True,
            'check_interval': 3600,  # seconds
            'max_retries': 3,
            'timeout': 30,
            'verify_ssl': True,
            'concurrent_downloads': 3,
            'enable_background_updates': False,
            'notify_on_update': True,
            'max_database_size_mb': 200,
        }

        self._load_user_config()

        self.stats = {
            'total_updates': 0,
            'last_successful': None,
            'errors': []
        }

        self._init_database()

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_base_dir() -> Path:
        """Locate the ZWYRM base directory"""
        # Prefer ~/.zwyrm if it exists
        user_base = Path.home() / '.zwyrm'
        if user_base.exists():
            return user_base
        # Fall back to cwd
        return Path('.')

    def _load_user_config(self):
        """Load configuration from config.yaml if present"""
        if not YAML_AVAILABLE:
            return

        config_candidates = [
            self.base_dir / 'config.yaml',
            Path('config.yaml'),
        ]

        for cfg_path in config_candidates:
            if cfg_path.exists():
                try:
                    with open(cfg_path, 'r') as f:
                        user_cfg = yaml.safe_load(f) or {}
                    updates = user_cfg.get('updates', {})
                    for key, val in updates.items():
                        if key in self.config:
                            self.config[key] = val

                    # Load custom update sources
                    for url in updates.get('update_urls', []):
                        if not any(s['url'] == url for s in self.update_sources):
                            self.update_sources.append({
                                'name': 'Custom',
                                'url': url,
                                'type': 'md5',
                                'enabled': True,
                                'priority': 99,
                            })
                    break
                except Exception:
                    pass

    def _init_database(self):
        """Initialize SQLite database"""
        if not SQLITE_AVAILABLE:
            return

        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()

            c.execute('''CREATE TABLE IF NOT EXISTS md5_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE NOT NULL,
                malware_name TEXT,
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                severity TEXT DEFAULT "medium",
                tags TEXT DEFAULT ""
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS sha256_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT UNIQUE NOT NULL,
                malware_name TEXT,
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                severity TEXT DEFAULT "medium",
                tags TEXT DEFAULT ""
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS string_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE NOT NULL,
                description TEXT,
                malware_name TEXT,
                source TEXT,
                severity TEXT DEFAULT "medium"
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS yara_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT UNIQUE NOT NULL,
                rule_content TEXT,
                author TEXT,
                description TEXT,
                created TEXT,
                updated TEXT,
                source TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                signatures_added INTEGER DEFAULT 0,
                signatures_removed INTEGER DEFAULT 0,
                duration REAL DEFAULT 0,
                success INTEGER DEFAULT 0,
                error_message TEXT
            )''')

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database init warning: {e}")

    # ------------------------------------------------------------------
    # Update scheduling
    # ------------------------------------------------------------------

    def get_last_update(self) -> str:
        """Return formatted last update time string"""
        if self.last_update_file.exists():
            try:
                with open(self.last_update_file, 'r') as f:
                    data = json.load(f)
                ts = data.get('timestamp')
                if ts:
                    dt = datetime.fromisoformat(ts)
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                pass
        return 'Never'

    def get_last_update_datetime(self) -> Optional[datetime]:
        """Return last update as datetime object"""
        if self.last_update_file.exists():
            try:
                with open(self.last_update_file, 'r') as f:
                    data = json.load(f)
                ts = data.get('timestamp')
                if ts:
                    return datetime.fromisoformat(ts)
            except Exception:
                pass
        return None

    def _set_last_update(self, source: str = None, added: int = 0, removed: int = 0):
        """Record a successful update"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'source': source or 'unknown',
            'signatures_added': added,
            'signatures_removed': removed,
            'version': '2.0',
        }
        try:
            with open(self.last_update_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

        self.stats['last_successful'] = data['timestamp']
        self.stats['total_updates'] += 1

    def check_for_updates(self) -> bool:
        """Return True if an update should be run"""
        last = self.get_last_update_datetime()
        if not last:
            return True
        elapsed = (datetime.now() - last).total_seconds()
        return elapsed > self.config['check_interval']

    # ------------------------------------------------------------------
    # Main update orchestrator
    # ------------------------------------------------------------------

    def update_signatures(self, force: bool = False) -> bool:
        """
        Update signatures. Returns True if any update succeeded.
        """
        if not force and not self.check_for_updates():
            print("Signatures are up to date.")
            return False

        if not REQUESTS_AVAILABLE:
            print("Warning: 'requests' package not installed. Cannot download signatures.")
            print("  Install with: pip install requests")
            return False

        print("Checking for signature updates...")

        total_added = 0
        sources_updated = 0

        enabled = sorted(
            [s for s in self.update_sources if s.get('enabled', True)],
            key=lambda x: x.get('priority', 99)
        )

        workers = min(self.config['concurrent_downloads'], len(enabled))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(workers, 1)) as ex:
            future_map = {ex.submit(self._download_source, s): s for s in enabled}

            for future in concurrent.futures.as_completed(future_map):
                source = future_map[future]
                try:
                    content = future.result(timeout=self.config['timeout'] * 2)
                    if content:
                        result = self._process_content(source, content)
                        if result.get('success'):
                            sources_updated += 1
                            total_added += result.get('added', 0)
                            print(f"  ✓ {source['name']}: +{result['added']} signatures")
                        else:
                            print(f"  ✗ {source['name']}: {result.get('error', 'parse error')}")
                except Exception as e:
                    print(f"  ✗ {source['name']}: {e}")

        if sources_updated > 0:
            self._set_last_update(
                source=f"{sources_updated} sources",
                added=total_added
            )
            print(f"\n✓ Updated {sources_updated} source(s), +{total_added} new signatures.")
            return True

        print("No updates were applied.")
        return False

    # ------------------------------------------------------------------
    # Downloading
    # ------------------------------------------------------------------

    def _download_source(self, source: Dict) -> Optional[str]:
        """Download from a source URL with retries"""
        url = source['url']
        headers = {'User-Agent': 'ZWYRM-AntiVirus/2.0'}

        for attempt in range(self.config['max_retries']):
            try:
                resp = requests.get(
                    url, headers=headers,
                    timeout=self.config['timeout'],
                    verify=self.config['verify_ssl'],
                    stream=True
                )
                resp.raise_for_status()

                # Read with size cap (50MB)
                chunks = []
                size = 0
                for chunk in resp.iter_content(chunk_size=65536):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 50 * 1024 * 1024:
                        break

                return b''.join(chunks).decode('utf-8', errors='ignore')

            except Exception as e:
                if attempt < self.config['max_retries'] - 1:
                    time.sleep(2 ** attempt)
                else:
                    raise

        return None

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _process_content(self, source: Dict, content: str) -> Dict:
        """Dispatch to the right parser based on source type"""
        stype = source.get('type', 'md5')
        name = source.get('name', 'unknown')

        if stype == 'md5':
            return self._process_md5_hashes(content, name)
        elif stype == 'sha256':
            return self._process_sha256_hashes(content, name)
        elif stype == 'vxdb':
            return self._process_vxdb_format(content, name)
        elif stype == 'domain':
            return self._process_domain_list(content, name)
        elif stype == 'json':
            return self._process_json_format(content, name)
        else:
            return {'success': False, 'error': f'Unknown type: {stype}', 'added': 0}

    def _process_md5_hashes(self, content: str, source_name: str) -> Dict:
        """Parse plain MD5 hash list"""
        if not SQLITE_AVAILABLE:
            return {'success': False, 'error': 'sqlite3 unavailable', 'added': 0}

        added = 0
        now = datetime.now().isoformat()

        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue

                parts = line.split(None, 1)
                h = parts[0].lower()

                if len(h) != 32 or not all(x in '0123456789abcdef' for x in h):
                    continue

                name = parts[1].strip() if len(parts) > 1 else 'Unknown'

                c.execute("SELECT id FROM md5_signatures WHERE hash=?", (h,))
                if c.fetchone():
                    c.execute("UPDATE md5_signatures SET last_seen=? WHERE hash=?", (now, h))
                else:
                    c.execute(
                        "INSERT INTO md5_signatures(hash,malware_name,first_seen,last_seen,source) VALUES(?,?,?,?,?)",
                        (h, name[:200], now, now, source_name)
                    )
                    added += 1

            conn.commit()
            total = c.execute("SELECT COUNT(*) FROM md5_signatures").fetchone()[0]
            conn.close()

            return {'success': True, 'added': added, 'removed': 0, 'total': total}

        except Exception as e:
            return {'success': False, 'error': str(e), 'added': 0}

    def _process_sha256_hashes(self, content: str, source_name: str) -> Dict:
        """Parse plain SHA256 hash list"""
        if not SQLITE_AVAILABLE:
            return {'success': False, 'error': 'sqlite3 unavailable', 'added': 0}

        added = 0
        now = datetime.now().isoformat()

        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue

                parts = line.split(None, 1)
                h = parts[0].lower()

                if len(h) != 64 or not all(x in '0123456789abcdef' for x in h):
                    continue

                name = parts[1].strip() if len(parts) > 1 else 'Unknown'

                c.execute("SELECT id FROM sha256_signatures WHERE hash=?", (h,))
                if c.fetchone():
                    c.execute("UPDATE sha256_signatures SET last_seen=? WHERE hash=?", (now, h))
                else:
                    c.execute(
                        "INSERT INTO sha256_signatures(hash,malware_name,first_seen,last_seen,source) VALUES(?,?,?,?,?)",
                        (h, name[:200], now, now, source_name)
                    )
                    added += 1

            conn.commit()
            total = c.execute("SELECT COUNT(*) FROM sha256_signatures").fetchone()[0]
            conn.close()

            return {'success': True, 'added': added, 'removed': 0, 'total': total}

        except Exception as e:
            return {'success': False, 'error': str(e), 'added': 0}

    def _process_vxdb_format(self, content: str, source_name: str) -> Dict:
        """Parse vxHeaven-style database"""
        if not SQLITE_AVAILABLE:
            return {'success': False, 'error': 'sqlite3 unavailable', 'added': 0}

        added = 0
        now = datetime.now().isoformat()

        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()

            current_name = None
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('Name:'):
                    current_name = line[5:].strip()
                elif line.startswith('MD5:'):
                    h = line[4:].strip().lower()
                    if current_name and len(h) == 32:
                        c.execute("SELECT id FROM md5_signatures WHERE hash=?", (h,))
                        if not c.fetchone():
                            c.execute(
                                "INSERT INTO md5_signatures(hash,malware_name,first_seen,last_seen,source) VALUES(?,?,?,?,?)",
                                (h, current_name[:200], now, now, source_name)
                            )
                            added += 1

            conn.commit()
            total = c.execute("SELECT COUNT(*) FROM md5_signatures").fetchone()[0]
            conn.close()

            return {'success': True, 'added': added, 'removed': 0, 'total': total}

        except Exception as e:
            return {'success': False, 'error': str(e), 'added': 0}

    def _process_domain_list(self, content: str, source_name: str) -> Dict:
        """Parse a domain blacklist and store as string patterns"""
        if not SQLITE_AVAILABLE:
            return {'success': False, 'error': 'sqlite3 unavailable', 'added': 0}

        added = 0
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue

                # Strip hosts-file prefixes like "127.0.0.1 "
                parts = line.split()
                domain = parts[-1] if parts else ''
                if not domain or '.' not in domain:
                    continue

                c.execute("SELECT id FROM string_patterns WHERE pattern=?", (domain,))
                if not c.fetchone():
                    c.execute(
                        "INSERT INTO string_patterns(pattern,description,malware_name,source,severity) VALUES(?,?,?,?,?)",
                        (domain, 'Malicious domain', 'Unknown', source_name, 'medium')
                    )
                    added += 1

            conn.commit()
            total = c.execute("SELECT COUNT(*) FROM string_patterns").fetchone()[0]
            conn.close()

            return {'success': True, 'added': added, 'removed': 0, 'total': total}

        except Exception as e:
            return {'success': False, 'error': str(e), 'added': 0}

    def _process_json_format(self, content: str, source_name: str) -> Dict:
        """Parse ZWYRM-format JSON signature bundle"""
        if not SQLITE_AVAILABLE:
            return {'success': False, 'error': 'sqlite3 unavailable', 'added': 0}

        added = 0
        try:
            data = json.loads(content)
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()
            now = datetime.now().isoformat()

            for h in data.get('md5_hashes', {}).keys():
                h = h.lower()
                if len(h) == 32:
                    c.execute("SELECT id FROM md5_signatures WHERE hash=?", (h,))
                    if not c.fetchone():
                        c.execute(
                            "INSERT INTO md5_signatures(hash,malware_name,first_seen,last_seen,source) VALUES(?,?,?,?,?)",
                            (h, data['md5_hashes'].get(h, 'Unknown'), now, now, source_name)
                        )
                        added += 1

            for h in data.get('sha256_hashes', {}).keys():
                h = h.lower()
                if len(h) == 64:
                    c.execute("SELECT id FROM sha256_signatures WHERE hash=?", (h,))
                    if not c.fetchone():
                        c.execute(
                            "INSERT INTO sha256_signatures(hash,malware_name,first_seen,last_seen,source) VALUES(?,?,?,?,?)",
                            (h, data['sha256_hashes'].get(h, 'Unknown'), now, now, source_name)
                        )
                        added += 1

            conn.commit()
            conn.close()

            return {'success': True, 'added': added, 'removed': 0, 'total': added}

        except Exception as e:
            return {'success': False, 'error': str(e), 'added': 0}

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_signature_count(self) -> int:
        """Return total number of signatures across all tables"""
        if not SQLITE_AVAILABLE or not self.signatures_sqlite.exists():
            # Fall back to JSON database
            try:
                with open(self.signatures_db, 'r') as f:
                    data = json.load(f)
                return (
                    len(data.get('md5_hashes', {})) +
                    len(data.get('sha256_hashes', {})) +
                    len(data.get('string_patterns', []))
                )
            except Exception:
                return 0

        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()
            total = 0
            for tbl in ('md5_signatures', 'sha256_signatures', 'string_patterns', 'yara_rules'):
                try:
                    row = c.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
                    total += row[0] if row else 0
                except sqlite3.OperationalError:
                    pass
            conn.close()
            return total
        except Exception:
            return 0

    def get_signature_breakdown(self) -> Dict[str, int]:
        """Return per-table signature counts"""
        if not SQLITE_AVAILABLE or not self.signatures_sqlite.exists():
            return {'md5': 0, 'sha256': 0, 'patterns': 0, 'yara': 0}

        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()
            counts = {}
            for label, tbl in [('md5', 'md5_signatures'), ('sha256', 'sha256_signatures'),
                                 ('patterns', 'string_patterns'), ('yara', 'yara_rules')]:
                try:
                    counts[label] = c.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
                except sqlite3.OperationalError:
                    counts[label] = 0
            conn.close()
            return counts
        except Exception:
            return {'md5': 0, 'sha256': 0, 'patterns': 0, 'yara': 0}

    def get_statistics(self) -> Dict:
        """Return update statistics"""
        return {
            'total_updates': self.stats['total_updates'],
            'last_successful': self.stats['last_successful'],
            'signature_count': self.get_signature_count(),
            'breakdown': self.get_signature_breakdown(),
        }

    def cleanup_old_signatures(self, days_old: int = 90):
        """Remove signatures not seen in `days_old` days"""
        if not SQLITE_AVAILABLE:
            return

        try:
            cutoff = (datetime.now() - timedelta(days=days_old)).isoformat()
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()

            for tbl in ('md5_signatures', 'sha256_signatures'):
                try:
                    c.execute(f"DELETE FROM {tbl} WHERE last_seen < ?", (cutoff,))
                except sqlite3.OperationalError:
                    pass

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Cleanup error: {e}")

    def start_background_updater(self):
        """Start a background update thread (daemon)"""
        if not self.config.get('enable_background_updates', False):
            return

        def _loop():
            while True:
                time.sleep(self.config['check_interval'])
                try:
                    if self.check_for_updates():
                        self.update_signatures()
                except Exception as e:
                    print(f"Background update error: {e}")
                    time.sleep(60)

        t = threading.Thread(target=_loop, daemon=True)
        t.start()


# Alias for backward compatibility
SignatureUpdater = EnhancedSignatureUpdater
