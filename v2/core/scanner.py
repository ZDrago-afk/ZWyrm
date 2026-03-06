#!/usr/bin/env python3
# core/scanner.py - Enhanced with multi-threading and caching

import os, hashlib, json, math, threading, queue, time, sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple

try:
    import yara; YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import mmap; MMAP_AVAILABLE = True
except ImportError:
    MMAP_AVAILABLE = False

try:
    import psutil; PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class EnhancedZWYRMScanner:
    def __init__(self):
        self.signatures = self.load_signatures()
        self.whitelist = self.load_whitelist()
        self.suspicious_extensions = {
            '.exe','.dll','.so','.bat','.cmd','.vbs','.js','.ps1',
            '.sh','.py','.pl','.rb','.php','.scr','.pif','.com','.jar','.class','.apk'
        }
        self.hash_cache = {}
        self.cache_ttl = 3600
        self.cache_timestamps = {}
        self.max_workers = 4
        self.yara_rules = None
        self.compile_yara_rules()
        self.stats = {'files_scanned':0,'threats_found':0,'cache_hits':0,'scan_time':0}

    def _find_base_dir(self) -> Path:
        user_base = Path.home() / '.zwyrm'
        if user_base.exists(): return user_base
        return Path('.')

    def load_signatures(self) -> Dict:
        base = self._find_base_dir()
        sqlite_path = base / 'database' / 'signatures.sqlite'
        if sqlite_path.exists():
            try:
                conn = sqlite3.connect(str(sqlite_path))
                c = conn.cursor()
                sigs = {'md5': set(), 'sha256': set()}
                try: sigs['md5'] = {r[0] for r in c.execute("SELECT hash FROM md5_signatures").fetchall()}
                except: pass
                try: sigs['sha256'] = {r[0] for r in c.execute("SELECT hash FROM sha256_signatures").fetchall()}
                except: pass
                conn.close(); return sigs
            except: pass
        json_path = base / 'database' / 'signatures.db'
        if json_path.exists():
            try:
                with open(json_path) as f: data = json.load(f)
                return {'md5': set(data.get('md5_hashes',{}).keys()), 'sha256': set(data.get('sha256_hashes',{}).keys())}
            except: pass
        return {'md5': set(), 'sha256': set()}

    def load_whitelist(self) -> Set[str]:
        base = self._find_base_dir()
        wl_path = base / 'database' / 'whitelist.db'
        if wl_path.exists():
            try:
                with open(wl_path) as f: data = json.load(f)
                return set(data) if isinstance(data, list) else set(data.keys())
            except: pass
        return set()

    def compile_yara_rules(self):
        if not YARA_AVAILABLE: return
        try:
            base = self._find_base_dir()
            rules_dir = base / 'database' / 'yara_rules'
            if not rules_dir.exists(): rules_dir = Path('database/yara_rules')
            if rules_dir.exists():
                yara_files = list(rules_dir.glob('*.yar')) + list(rules_dir.glob('*.yara'))
                if yara_files:
                    sources = {}
                    for yf in yara_files:
                        try: sources[str(yf)] = yf.read_text()
                        except: pass
                    if sources:
                        self.yara_rules = yara.compile(sources=sources)
                        print(f"✓ Loaded {len(yara_files)} YARA rule files")
        except Exception as e:
            print(f"⚠ YARA rules error: {e}")

    def calculate_hashes(self, filepath: str, use_cache: bool = True) -> Tuple:
        try: mtime = os.path.getmtime(filepath)
        except: return None, None, None
        if use_cache:
            ck = f"{filepath}_{mtime}"
            if ck in self.hash_cache and time.time() - self.cache_timestamps.get(ck,0) < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return self.hash_cache[ck]
        md5 = hashlib.md5(); sha256 = hashlib.sha256(); sha1 = hashlib.sha1()
        try:
            if MMAP_AVAILABLE and os.path.getsize(filepath) > 0:
                with open(filepath,'rb') as f:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        offset = 0
                        while offset < len(mm):
                            chunk = mm[offset:offset+8192]
                            md5.update(chunk); sha256.update(chunk); sha1.update(chunk)
                            offset += len(chunk)
            else:
                with open(filepath,'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        md5.update(chunk); sha256.update(chunk); sha1.update(chunk)
            hashes = (md5.hexdigest(), sha256.hexdigest(), sha1.hexdigest())
            if use_cache:
                ck = f"{filepath}_{mtime}"
                self.hash_cache[ck] = hashes; self.cache_timestamps[ck] = time.time()
                self._evict_cache()
            return hashes
        except: return None, None, None

    def _evict_cache(self):
        if len(self.hash_cache) < 1000: return
        now = time.time()
        for k in [k for k,ts in self.cache_timestamps.items() if now-ts > self.cache_ttl]:
            self.hash_cache.pop(k,None); self.cache_timestamps.pop(k,None)

    def check_signatures(self, md5_hash, sha256_hash, filepath) -> List[Dict]:
        threats = []
        if md5_hash and md5_hash in self.signatures.get('md5', set()):
            threats.append({'type':'signature','name':f'Known malware (MD5)','severity':'high','hash':md5_hash,'hash_type':'md5'})
        if sha256_hash and sha256_hash in self.signatures.get('sha256', set()):
            threats.append({'type':'signature','name':f'Known malware (SHA256)','severity':'high','hash':sha256_hash,'hash_type':'sha256'})
        return threats

    def scan_file_with_yara(self, filepath: str) -> List[Dict]:
        if not YARA_AVAILABLE or not self.yara_rules: return []
        try:
            return [{'type':'yara_match','name':m.rule,'tags':list(m.tags),'severity':m.meta.get('severity','medium')} for m in self.yara_rules.match(filepath)]
        except: return []

    def scan_single_file(self, filepath: str) -> Dict:
        result = {'filepath':filepath,'filename':os.path.basename(filepath),'threats':[],'clean':True,'timestamp':datetime.now().isoformat(),'warnings':[],'scan_details':{}}
        try:
            stat = os.stat(filepath)
            result['size'] = stat.st_size
            result['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            if stat.st_size > 500*1024*1024:
                result['skipped'] = 'File too large'; return result
            md5, sha256, sha1 = self.calculate_hashes(filepath)
            if not md5:
                result['error'] = 'Could not read file'; return result
            result['hashes'] = {'md5':md5,'sha256':sha256,'sha1':sha1}
            if md5 in self.whitelist or sha256 in self.whitelist:
                result['whitelisted'] = True; return result
            for t in self.check_signatures(md5, sha256, filepath):
                result['threats'].append(t); result['clean'] = False
            for t in self.scan_file_with_yara(filepath):
                result['threats'].append(t); result['clean'] = False
            ext = Path(filepath).suffix.lower()
            if ext in self.suspicious_extensions:
                result['warnings'].append(f'Suspicious extension: {ext}')
            for t in self.heuristic_checks(filepath):
                result['threats'].append(t); result['clean'] = False
            result['scan_details']['scan_methods'] = ['signature','yara','heuristic']
            result['scan_details']['file_type'] = self.detect_file_type(filepath)
            self.stats['files_scanned'] += 1
        except PermissionError:
            result['error'] = 'Permission denied'
        except Exception as e:
            result['error'] = str(e)
        return result

    def heuristic_checks(self, filepath: str) -> List[Dict]:
        threats = []
        try:
            filename = os.path.basename(filepath)
            if filename.count('.') > 1:
                double_ext = ''.join(Path(filename).suffixes[-2:]).lower()
                bad = {'.txt.exe':'Executable disguised as text','.jpg.exe':'Executable disguised as image','.pdf.exe':'Executable disguised as PDF','.doc.exe':'Executable disguised as document'}
                if double_ext in bad: threats.append({'type':'heuristic','name':bad[double_ext],'details':f'Double ext: {double_ext}','severity':'high'})
            size = os.path.getsize(filepath); ext = Path(filepath).suffix.lower()
            if ext in ['.exe','.dll'] and size < 1024:
                threats.append({'type':'heuristic','name':'Tiny executable','details':f'{size} bytes','severity':'medium'})
            if ext in ['.exe','.dll','.sys']:
                ent = self.calculate_file_entropy(filepath)
                if ent > 7.0: threats.append({'type':'heuristic','name':'Packed/encrypted executable','details':f'Entropy: {ent:.2f}','severity':'medium'})
        except: pass
        return threats

    def calculate_file_entropy(self, filepath: str, sample_size: int = 8192) -> float:
        try:
            with open(filepath,'rb') as f: data = f.read(sample_size)
            if not data: return 0.0
            counts = [0]*256
            for b in data: counts[b] += 1
            n = len(data)
            return -sum((c/n)*math.log2(c/n) for c in counts if c > 0)
        except: return 0.0

    def detect_file_type(self, filepath: str) -> str:
        try:
            import magic; return magic.from_file(filepath, mime=True)
        except:
            ext = Path(filepath).suffix.lower()
            return {'.exe':'application/x-dosexec','.dll':'application/x-dosexec','.pdf':'application/pdf','.py':'text/x-python','.sh':'text/x-shellscript','.zip':'application/zip'}.get(ext,'application/octet-stream')

    def scan_directory(self, directory: str, recursive: bool = True) -> Dict:
        return self.scan_directory_parallel(directory, recursive=recursive)

    def scan_directory_parallel(self, directory: str, recursive: bool = True, max_threads: int = None) -> Dict:
        if max_threads is None: max_threads = self.max_workers
        results = {'scan_start':datetime.now().isoformat(),'directory':directory,'files_scanned':0,'threats_found':0,'clean_files':0,'errors':0,'threats':[],'scan_mode':'parallel'}
        try:
            path = Path(directory)
            if not path.exists():
                results['error'] = f'Not found: {directory}'; results['scan_end'] = datetime.now().isoformat(); return results
            gen = path.rglob('*') if recursive else path.glob('*')
            files = [str(fp) for fp in gen if fp.is_file()]
            with ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = {ex.submit(self.scan_single_file, fp): fp for fp in files[:5000]}
                for fut in as_completed(futures):
                    try:
                        r = fut.result(timeout=30)
                        results['files_scanned'] += 1
                        if not r.get('clean',True): results['threats_found'] += 1; results['threats'].append(r)
                        else: results['clean_files'] += 1
                    except: results['errors'] += 1
            results['scan_end'] = datetime.now().isoformat()
            s = datetime.fromisoformat(results['scan_start']); e = datetime.fromisoformat(results['scan_end'])
            results['duration'] = (e-s).total_seconds()
        except Exception as ex: results['error'] = str(ex); results['scan_end'] = datetime.now().isoformat()
        return results

    def quick_scan(self) -> Dict:
        base = self._find_base_dir()
        quick_paths = [os.path.expanduser('~/Downloads'),os.path.expanduser('~/Desktop'),'/tmp','/var/tmp']
        try:
            import yaml
            cfg = (base/'config.yaml')
            if cfg.exists():
                data = yaml.safe_load(cfg.read_text()) or {}
                paths = data.get('scanning',{}).get('quick_scan_paths',[])
                if paths: quick_paths = [os.path.expanduser(p) for p in paths]
        except: pass
        all_r = {'scan_start':datetime.now().isoformat(),'scan_type':'quick','files_scanned':0,'threats_found':0,'clean_files':0,'threats':[],'details':[]}
        for p in quick_paths:
            if os.path.exists(p):
                r = self.scan_directory_parallel(p, recursive=False)
                all_r['files_scanned'] += r.get('files_scanned',0); all_r['threats_found'] += r.get('threats_found',0)
                all_r['clean_files'] += r.get('clean_files',0); all_r['threats'].extend(r.get('threats',[])); all_r['details'].append(r)
        all_r['scan_end'] = datetime.now().isoformat()
        return all_r

    def full_system_scan(self) -> Dict:
        threads = self.max_workers
        if PSUTIL_AVAILABLE:
            cpu = psutil.cpu_percent(interval=1)
            if cpu > 80: threads = 2
            elif cpu > 60: threads = 3
        system_paths = ['/home','/tmp','/var/tmp','/usr/local/bin']
        all_r = {'scan_start':datetime.now().isoformat(),'scan_type':'full','files_scanned':0,'threats_found':0,'clean_files':0,'threats':[],'details':[]}
        for p in system_paths:
            if os.path.exists(p):
                r = self.scan_directory_parallel(p, recursive=True, max_threads=threads)
                all_r['files_scanned'] += r.get('files_scanned',0); all_r['threats_found'] += r.get('threats_found',0)
                all_r['clean_files'] += r.get('clean_files',0); all_r['threats'].extend(r.get('threats',[])); all_r['details'].append(r)
        all_r['scan_end'] = datetime.now().isoformat()
        return all_r

    def smart_scan(self, path: str) -> Dict:
        threads = self.max_workers
        if PSUTIL_AVAILABLE:
            cpu = psutil.cpu_percent(interval=1); mem = psutil.virtual_memory().percent
            if cpu > 80 or mem > 80: threads = 2
            elif cpu > 60 or mem > 60: threads = 3
        return self.scan_single_file(path) if os.path.isfile(path) else self.scan_directory_parallel(path, recursive=True, max_threads=threads)

# Backward-compatibility alias
ZWYRMScanner = EnhancedZWYRMScanner
