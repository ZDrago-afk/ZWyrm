#!/usr/bin/env python3
# core/scanner.py - Enhanced with multi-threading, caching, and complete implementation

import os
import math
import hashlib
import json
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple

try:
    import mmap
    MMAP_AVAILABLE = True
except ImportError:
    MMAP_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import sqlite3
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False


class EnhancedZWYRMScanner:
    def __init__(self):
        self.signatures = self.load_signatures()
        self.whitelist = self.load_whitelist()
        self.suspicious_extensions = {
            '.exe', '.dll', '.so', '.bat', '.cmd', '.vbs',
            '.js', '.ps1', '.sh', '.py', '.pl', '.rb', '.php',
            '.scr', '.pif', '.com', '.jar', '.class', '.apk'
        }

        # Performance optimization
        self.hash_cache: Dict[str, Tuple] = {}
        self.cache_ttl = 3600  # 1 hour
        self.cache_timestamps: Dict[str, float] = {}

        # Threading
        self.max_workers = 4
        self.scan_queue: queue.Queue = queue.Queue()
        self.results_queue: queue.Queue = queue.Queue()

        # YARA rules
        self.yara_rules = None
        self.compile_yara_rules()

        # Exclude paths
        self.exclude_paths = [
            '/proc', '/sys', '/dev', '/run', '/snap'
        ]

        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'cache_hits': 0,
            'scan_time': 0
        }

    # ------------------------------------------------------------------
    # Database loading
    # ------------------------------------------------------------------

    def load_signatures(self) -> Dict:
        """Load virus signatures from database"""
        signatures = {
            'md5_hashes': {},
            'sha256_hashes': {},
            'string_patterns': [],
            'yara_rules': []
        }

        # Try SQLite first
        sqlite_path = Path('database/signatures.sqlite')
        if SQLITE_AVAILABLE and sqlite_path.exists():
            try:
                conn = sqlite3.connect(str(sqlite_path))
                cursor = conn.cursor()

                # Load MD5 hashes
                try:
                    cursor.execute("SELECT hash, malware_name FROM md5_signatures")
                    for row in cursor.fetchall():
                        signatures['md5_hashes'][row[0]] = row[1] or 'Unknown'
                except sqlite3.OperationalError:
                    pass

                # Load SHA256 hashes
                try:
                    cursor.execute("SELECT hash, malware_name FROM sha256_signatures")
                    for row in cursor.fetchall():
                        signatures['sha256_hashes'][row[0]] = row[1] or 'Unknown'
                except sqlite3.OperationalError:
                    pass

                # Load string patterns
                try:
                    cursor.execute("SELECT pattern FROM string_patterns")
                    signatures['string_patterns'] = [row[0] for row in cursor.fetchall()]
                except sqlite3.OperationalError:
                    pass

                conn.close()
            except Exception as e:
                pass  # Fall through to JSON

        # Fall back to JSON database
        json_path = Path('database/signatures.db')
        if json_path.exists() and json_path.stat().st_size > 0:
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        signatures.update(data)
            except Exception:
                pass

        return signatures

    def load_whitelist(self) -> Set[str]:
        """Load whitelist from database"""
        whitelist = set()

        whitelist_path = Path('database/whitelist.db')
        if whitelist_path.exists() and whitelist_path.stat().st_size > 0:
            try:
                with open(whitelist_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        whitelist = set(data)
                    elif isinstance(data, dict):
                        whitelist = set(data.get('hashes', []))
            except Exception:
                pass

        return whitelist

    def reload_signatures(self):
        """Reload signatures from disk"""
        self.signatures = self.load_signatures()
        self.whitelist = self.load_whitelist()

    # ------------------------------------------------------------------
    # YARA compilation
    # ------------------------------------------------------------------

    def compile_yara_rules(self):
        """Compile YARA rules for faster scanning"""
        if not YARA_AVAILABLE:
            return

        try:
            rules_dir = Path('database/yara_rules')
            if rules_dir.exists():
                yara_files = list(rules_dir.glob('*.yar')) + list(rules_dir.glob('*.yara'))
                if yara_files:
                    sources = {}
                    for yf in yara_files:
                        sources[yf.stem] = str(yf)
                    self.yara_rules = yara.compile(filepaths=sources)
        except Exception as e:
            self.yara_rules = None

    # ------------------------------------------------------------------
    # Hash utilities
    # ------------------------------------------------------------------

    def calculate_hashes(self, filepath: str, use_cache: bool = True) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Calculate MD5, SHA256, SHA1 with caching"""
        try:
            mtime = os.path.getmtime(filepath)
            cache_key = f"{filepath}_{mtime}"

            if use_cache and cache_key in self.hash_cache:
                # Check TTL
                if time.time() - self.cache_timestamps.get(cache_key, 0) < self.cache_ttl:
                    self.stats['cache_hits'] += 1
                    return self.hash_cache[cache_key]

            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            sha1 = hashlib.sha1()

            file_size = os.path.getsize(filepath)

            if MMAP_AVAILABLE and file_size > 0:
                with open(filepath, 'rb') as f:
                    try:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            chunk_size = 65536
                            offset = 0
                            while offset < len(mm):
                                chunk = mm[offset:offset + chunk_size]
                                md5.update(chunk)
                                sha256.update(chunk)
                                sha1.update(chunk)
                                offset += len(chunk)
                    except (ValueError, mmap.error):
                        # File too small or other issue, fall back to normal read
                        f.seek(0)
                        for chunk in iter(lambda: f.read(65536), b''):
                            md5.update(chunk)
                            sha256.update(chunk)
                            sha1.update(chunk)
            else:
                with open(filepath, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        md5.update(chunk)
                        sha256.update(chunk)
                        sha1.update(chunk)

            hashes = (md5.hexdigest(), sha256.hexdigest(), sha1.hexdigest())

            if use_cache:
                self.hash_cache[cache_key] = hashes
                self.cache_timestamps[cache_key] = time.time()
                # Evict old cache entries
                if len(self.hash_cache) > 5000:
                    self._evict_cache()

            return hashes

        except Exception:
            return None, None, None

    def _evict_cache(self):
        """Evict old cache entries"""
        now = time.time()
        expired = [k for k, t in self.cache_timestamps.items() if now - t > self.cache_ttl]
        for k in expired:
            self.hash_cache.pop(k, None)
            self.cache_timestamps.pop(k, None)

    def calculate_file_entropy(self, filepath: str, sample_size: int = 65536) -> float:
        """Calculate Shannon entropy of file sample"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(sample_size)

            if not data:
                return 0.0

            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)

            return entropy
        except Exception:
            return 0.0

    # ------------------------------------------------------------------
    # Signature checking
    # ------------------------------------------------------------------

    def check_signatures(self, md5_hash: Optional[str], sha256_hash: Optional[str],
                          filepath: str) -> List[Dict]:
        """Check file against known signatures"""
        threats = []

        if md5_hash and md5_hash in self.signatures.get('md5_hashes', {}):
            malware_name = self.signatures['md5_hashes'][md5_hash]
            threats.append({
                'type': 'known_malware',
                'name': malware_name,
                'hash_type': 'md5',
                'hash': md5_hash,
                'severity': 'high'
            })

        if sha256_hash and sha256_hash in self.signatures.get('sha256_hashes', {}):
            malware_name = self.signatures['sha256_hashes'][sha256_hash]
            threats.append({
                'type': 'known_malware',
                'name': malware_name,
                'hash_type': 'sha256',
                'hash': sha256_hash,
                'severity': 'high'
            })

        # Check string patterns
        if self.signatures.get('string_patterns'):
            try:
                with open(filepath, 'rb') as f:
                    content = f.read(1024 * 1024)  # Read 1MB for pattern matching
                content_str = content.decode('latin-1', errors='ignore').lower()

                for pattern in self.signatures['string_patterns']:
                    if pattern.lower() in content_str:
                        threats.append({
                            'type': 'string_pattern',
                            'name': f'Pattern: {pattern[:50]}',
                            'severity': 'medium'
                        })
                        break  # One is enough to flag
            except Exception:
                pass

        return threats

    # ------------------------------------------------------------------
    # YARA scanning
    # ------------------------------------------------------------------

    def scan_file_with_yara(self, filepath: str) -> List[Dict]:
        """Scan file using YARA rules"""
        matches = []
        if not YARA_AVAILABLE or not self.yara_rules:
            return matches

        try:
            yara_matches = self.yara_rules.match(filepath, timeout=30)
            for match in yara_matches:
                matches.append({
                    'type': 'yara_match',
                    'name': match.rule,
                    'tags': list(match.tags),
                    'meta': dict(match.meta) if match.meta else {},
                    'severity': match.meta.get('severity', 'medium') if match.meta else 'medium'
                })
        except Exception:
            pass

        return matches

    # ------------------------------------------------------------------
    # File type detection
    # ------------------------------------------------------------------

    def detect_file_type(self, filepath: str) -> str:
        """Detect file type using magic numbers, fall back to extension"""
        try:
            import magic as libmagic
            return libmagic.from_file(filepath, mime=True)
        except Exception:
            pass

        # Magic number fallback
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)

            magic_map = {
                b'MZ': 'application/x-dosexec',
                b'\x7fELF': 'application/x-elf',
                b'\x89PNG': 'image/png',
                b'\xff\xd8\xff': 'image/jpeg',
                b'GIF8': 'image/gif',
                b'%PDF': 'application/pdf',
                b'PK\x03\x04': 'application/zip',
                b'\x1f\x8b': 'application/gzip',
                b'BZh': 'application/x-bzip2',
                b'Rar!': 'application/x-rar',
                b'#!/': 'text/x-shellscript',
                b'#!': 'text/x-script',
            }

            for magic_bytes, mime_type in magic_map.items():
                if header.startswith(magic_bytes):
                    return mime_type
        except Exception:
            pass

        # Extension fallback
        ext_map = {
            '.exe': 'application/x-dosexec', '.dll': 'application/x-dosexec',
            '.so': 'application/x-sharedlib', '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.zip': 'application/zip',
            '.tar': 'application/x-tar', '.gz': 'application/gzip',
            '.txt': 'text/plain', '.html': 'text/html',
            '.js': 'application/javascript', '.py': 'text/x-python',
            '.sh': 'text/x-shellscript', '.pl': 'text/x-perl',
            '.rb': 'text/x-ruby', '.php': 'text/x-php',
            '.bat': 'application/x-bat', '.cmd': 'application/x-bat',
            '.vbs': 'text/vbscript', '.ps1': 'text/x-powershell',
        }
        ext = Path(filepath).suffix.lower()
        return ext_map.get(ext, 'application/octet-stream')

    # ------------------------------------------------------------------
    # Heuristic checks
    # ------------------------------------------------------------------

    def heuristic_checks(self, filepath: str) -> List[Dict]:
        """Perform heuristic checks on file"""
        threats = []

        try:
            filename = os.path.basename(filepath)
            file_path = Path(filepath)
            file_size = os.path.getsize(filepath)
            ext = file_path.suffix.lower()

            # Double extension check
            if filename.count('.') > 1:
                suffixes = file_path.suffixes
                if len(suffixes) >= 2:
                    double_ext = ''.join(suffixes[-2:]).lower()
                    malware_double_exts = {
                        '.txt.exe': 'Executable disguised as text file',
                        '.jpg.exe': 'Executable disguised as image',
                        '.pdf.exe': 'Executable disguised as PDF',
                        '.doc.exe': 'Executable disguised as document',
                        '.zip.exe': 'Executable disguised as archive',
                        '.mp3.exe': 'Executable disguised as audio',
                        '.mp4.exe': 'Executable disguised as video',
                    }
                    if double_ext in malware_double_exts:
                        threats.append({
                            'type': 'heuristic',
                            'name': malware_double_exts[double_ext],
                            'details': f'Double extension: {double_ext}',
                            'severity': 'high'
                        })

            # Tiny executable
            if ext in ['.exe', '.dll'] and file_size > 0 and file_size < 1024:
                threats.append({
                    'type': 'heuristic',
                    'name': 'Tiny executable',
                    'details': f'Executable is unusually small ({file_size} bytes)',
                    'severity': 'medium'
                })

            # High entropy check for executables
            if ext in ['.exe', '.dll', '.sys', '.so']:
                entropy = self.calculate_file_entropy(filepath)
                if entropy > 7.0:
                    threats.append({
                        'type': 'heuristic',
                        'name': 'Packed/encrypted executable',
                        'details': f'High entropy: {entropy:.2f} (possible packing)',
                        'severity': 'medium'
                    })

            # Check for suspicious script content
            if ext in ['.sh', '.bash', '.py', '.pl', '.rb', '.php', '.js', '.vbs', '.ps1']:
                if file_size < 10 * 1024 * 1024:  # Under 10MB
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read(65536)

                        suspicious_patterns = [
                            ('eval(base64_decode', 'Base64 encoded eval'),
                            ('exec(base64', 'Base64 encoded exec'),
                            ('system(chr(', 'Chr-encoded system call'),
                            ('powershell -enc', 'Encoded PowerShell'),
                            ('powershell -e ', 'Encoded PowerShell'),
                            ('/dev/tcp/', 'Reverse shell indicator'),
                            ('bash -i >&', 'Reverse shell indicator'),
                            ('nc -e /bin', 'Netcat reverse shell'),
                            ('rm -rf /', 'Destructive command'),
                            (':(){ :|:& };:', 'Fork bomb'),
                        ]

                        for pattern, description in suspicious_patterns:
                            if pattern.lower() in content.lower():
                                threats.append({
                                    'type': 'heuristic',
                                    'name': description,
                                    'details': f'Suspicious pattern found: {pattern}',
                                    'severity': 'high'
                                })
                    except Exception:
                        pass

        except Exception:
            pass

        return threats

    # ------------------------------------------------------------------
    # Core single-file scan
    # ------------------------------------------------------------------

    def scan_single_file(self, filepath: str) -> Dict:
        """Scan a single file for threats"""
        result = {
            'filepath': filepath,
            'filename': os.path.basename(filepath),
            'threats': [],
            'clean': True,
            'timestamp': datetime.now().isoformat(),
            'warnings': [],
            'scan_details': {}
        }

        try:
            if not os.path.exists(filepath):
                result['error'] = 'File not found'
                return result

            stat = os.stat(filepath)
            result['size'] = stat.st_size
            result['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()

            # Skip zero-byte files
            if stat.st_size == 0:
                result['warnings'].append('Zero-byte file')
                return result

            # Skip large files
            max_size = 500 * 1024 * 1024  # 500MB
            if stat.st_size > max_size:
                result['skipped'] = 'File too large'
                result['warnings'].append('File exceeds size limit (500MB)')
                return result

            # Skip excluded paths
            for excl in self.exclude_paths:
                if filepath.startswith(excl):
                    result['skipped'] = 'Excluded path'
                    return result

            # Calculate hashes
            md5_hash, sha256_hash, sha1_hash = self.calculate_hashes(filepath)
            if not md5_hash:
                result['error'] = 'Could not read file'
                return result

            result['hashes'] = {
                'md5': md5_hash,
                'sha256': sha256_hash,
                'sha1': sha1_hash
            }

            # Check whitelist
            if md5_hash in self.whitelist or (sha256_hash and sha256_hash in self.whitelist):
                result['whitelisted'] = True
                return result

            # 1. Signature-based detection
            sig_threats = self.check_signatures(md5_hash, sha256_hash, filepath)
            if sig_threats:
                result['threats'].extend(sig_threats)

            # 2. YARA scanning
            yara_threats = self.scan_file_with_yara(filepath)
            if yara_threats:
                result['threats'].extend(yara_threats)

            # 3. Heuristic checks
            heuristic_threats = self.heuristic_checks(filepath)
            if heuristic_threats:
                result['threats'].extend(heuristic_threats)

            # 4. Suspicious extension warning
            ext = Path(filepath).suffix.lower()
            if ext in self.suspicious_extensions:
                result['warnings'].append(f'Suspicious extension: {ext}')

            # 5. File type detection
            result['scan_details']['file_type'] = self.detect_file_type(filepath)
            result['scan_details']['scan_methods'] = ['signature', 'yara', 'heuristic']

            # 6. Executable permission check (Linux)
            if os.name == 'posix' and os.access(filepath, os.X_OK):
                allowed = {'.sh', '.py', '.pl', '.rb', '.php', '.exe', '.bin', '.run', ''}
                if ext not in allowed:
                    result['warnings'].append('Unexpected executable permission')

            result['clean'] = len(result['threats']) == 0

        except PermissionError:
            result['error'] = 'Permission denied'
            result['warnings'].append('Insufficient permissions to scan file')
        except Exception as e:
            result['error'] = str(e)
            result['warnings'].append(f'Scan error: {e}')

        return result

    # ------------------------------------------------------------------
    # Directory & system scanning
    # ------------------------------------------------------------------

    def scan_directory(self, directory: str, recursive: bool = True,
                       progress_callback=None) -> Dict:
        """Scan a directory (uses parallel scanning)"""
        return self.scan_directory_parallel(directory, recursive=recursive,
                                             progress_callback=progress_callback)

    def scan_directory_parallel(self, directory: str, recursive: bool = True,
                                 max_threads: Optional[int] = None,
                                 progress_callback=None) -> Dict:
        """Scan directory using parallel processing"""
        if max_threads is None:
            max_threads = self.max_workers

        results = {
            'scan_start': datetime.now().isoformat(),
            'directory': directory,
            'files_scanned': 0,
            'threats_found': 0,
            'clean_files': 0,
            'skipped_files': 0,
            'errors': 0,
            'threats': [],
            'file_results': [],
            'scan_mode': 'parallel'
        }

        try:
            path = Path(directory)
            if not path.exists():
                results['error'] = f'Directory not found: {directory}'
                return results

            if recursive:
                file_gen = path.rglob('*')
            else:
                file_gen = path.glob('*')

            all_files = []
            for fp in file_gen:
                if fp.is_file() and not fp.is_symlink():
                    # Skip excluded paths
                    skip = False
                    for excl in self.exclude_paths:
                        if str(fp).startswith(excl):
                            skip = True
                            break
                    if not skip:
                        all_files.append(str(fp))

            total_files = len(all_files)

            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_file = {
                    executor.submit(self.scan_single_file, fp): fp
                    for fp in all_files
                }

                for future in as_completed(future_to_file):
                    fp = future_to_file[future]
                    try:
                        file_result = future.result(timeout=60)
                        results['files_scanned'] += 1

                        if file_result.get('skipped'):
                            results['skipped_files'] += 1
                        elif not file_result.get('clean', True):
                            results['threats_found'] += 1
                            results['threats'].append(file_result)
                        else:
                            results['clean_files'] += 1

                        if progress_callback:
                            progress_callback(results['files_scanned'], total_files)

                    except Exception:
                        results['errors'] += 1

            results['scan_end'] = datetime.now().isoformat()
            start = datetime.fromisoformat(results['scan_start'])
            end = datetime.fromisoformat(results['scan_end'])
            results['duration'] = (end - start).total_seconds()
            results['performance'] = {
                'files_per_second': results['files_scanned'] / max(results['duration'], 0.01),
                'cache_hits': self.stats['cache_hits'],
                'threads_used': max_threads
            }

        except Exception as e:
            results['error'] = str(e)

        return results

    def quick_scan(self, path: Optional[str] = None) -> Dict:
        """Quick scan of common threat locations"""
        quick_paths = [
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/.local/share'),
            os.path.expanduser('~/Documents'),
            '/tmp',
            '/var/tmp',
        ]

        if path and os.path.exists(path):
            quick_paths = [path]

        combined = {
            'scan_start': datetime.now().isoformat(),
            'files_scanned': 0,
            'threats_found': 0,
            'clean_files': 0,
            'skipped_files': 0,
            'errors': 0,
            'threats': [],
            'scan_mode': 'quick',
            'details': []
        }

        for scan_path in quick_paths:
            if os.path.exists(scan_path):
                result = self.scan_directory_parallel(scan_path, recursive=True,
                                                       max_threads=2)
                combined['files_scanned'] += result.get('files_scanned', 0)
                combined['threats_found'] += result.get('threats_found', 0)
                combined['clean_files'] += result.get('clean_files', 0)
                combined['skipped_files'] += result.get('skipped_files', 0)
                combined['errors'] += result.get('errors', 0)
                combined['threats'].extend(result.get('threats', []))
                combined['details'].append(result)

        combined['scan_end'] = datetime.now().isoformat()
        return combined

    def full_system_scan(self) -> Dict:
        """Full system scan"""
        system_paths = [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin',
            '/usr/local/bin', '/lib', '/lib64', '/etc', '/boot',
            os.path.expanduser('~'),
            '/tmp', '/var/tmp',
        ]

        combined = {
            'scan_start': datetime.now().isoformat(),
            'files_scanned': 0,
            'threats_found': 0,
            'clean_files': 0,
            'skipped_files': 0,
            'errors': 0,
            'threats': [],
            'scan_mode': 'full',
            'details': []
        }

        threads = self.max_workers
        if PSUTIL_AVAILABLE:
            cpu = psutil.cpu_percent(interval=1)
            if cpu > 70:
                threads = 2

        for scan_path in system_paths:
            if os.path.exists(scan_path):
                result = self.scan_directory_parallel(scan_path, recursive=True,
                                                       max_threads=threads)
                combined['files_scanned'] += result.get('files_scanned', 0)
                combined['threats_found'] += result.get('threats_found', 0)
                combined['clean_files'] += result.get('clean_files', 0)
                combined['threats'].extend(result.get('threats', []))
                combined['details'].append(result)

        combined['scan_end'] = datetime.now().isoformat()
        start = datetime.fromisoformat(combined['scan_start'])
        end = datetime.fromisoformat(combined['scan_end'])
        combined['duration'] = (end - start).total_seconds()
        return combined

    def smart_scan(self, path: str) -> Dict:
        """Smart scanning that adapts based on system load"""
        max_threads = self.max_workers

        if PSUTIL_AVAILABLE:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent

                if cpu_percent > 80 or memory_percent > 80:
                    max_threads = 2
                elif cpu_percent > 60 or memory_percent > 60:
                    max_threads = 3
            except Exception:
                pass

        if os.path.isfile(path):
            return self.scan_single_file(path)
        else:
            return self.scan_directory_parallel(path, recursive=True,
                                                 max_threads=max_threads)


# Alias for backward compatibility
ZWYRMScanner = EnhancedZWYRMScanner
