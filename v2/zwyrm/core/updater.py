#!/usr/bin/env python3
# core/updater.py - Enhanced with multiple sources, verification, and CDN support

import json, hashlib, sqlite3, time, threading, os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import concurrent.futures

try:
    import requests; REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠ requests not installed — signature updates disabled. Run: pip install requests")

try:
    import yaml; YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class EnhancedSignatureUpdater:
    def __init__(self):
        base = Path.home() / '.zwyrm'
        if base.exists():
            self.base_dir = base
        else:
            self.base_dir = Path('.')
        self.signatures_db = self.base_dir / 'database' / 'signatures.db'
        self.signatures_sqlite = self.base_dir / 'database' / 'signatures.sqlite'
        self.config_file = self.base_dir / 'config.yaml'
        self.last_update_file = self.base_dir / 'database' / 'last_update.json'

        self.update_sources = [
            {'name':'MalwareBazaar','url':'https://bazaar.abuse.ch/export/txt/md5/full/','type':'md5','format':'text','enabled':True,'priority':1},
            {'name':'VirusShare','url':'https://virusshare.com/hashfiles/VirusShare_00000.md5','type':'md5','format':'text','enabled':True,'priority':2},
            {'name':'MalwareDomainList','url':'https://www.malwaredomainlist.com/hostslist/mdl.txt','type':'domain','format':'text','enabled':True,'priority':4},
            {'name':'ZWYRM Official','url':'https://api.zwyrm.com/signatures/latest','type':'json','format':'json','enabled':False,'priority':0},
        ]
        self.yara_sources = [
            {'name':'YARA Rules Project','url':'https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip','type':'zip','category':'malware'},
        ]
        self.config = {'auto_update':True,'check_interval':3600,'max_retries':3,'timeout':30,'verify_ssl':True,'concurrent_downloads':3,'enable_background_updates':True,'notify_on_update':True}
        self.load_user_config()
        self.stats = {'total_updates':0,'last_successful':None,'signatures_count':0,'errors':[]}
        self.init_database()

    def _find_db_dir(self) -> Path:
        d = self.base_dir / 'database'
        d.mkdir(parents=True, exist_ok=True)
        return d

    def load_user_config(self):
        if not YAML_AVAILABLE or not self.config_file.exists(): return
        try:
            with open(self.config_file) as f: uc = yaml.safe_load(f)
            if uc and 'updates' in uc:
                for k, v in uc['updates'].items():
                    if k in self.config: self.config[k] = v
        except: pass

    def init_database(self):
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS md5_signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT UNIQUE NOT NULL, malware_name TEXT, first_seen DATETIME, last_seen DATETIME, source TEXT, severity TEXT, tags TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS sha256_signatures (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT UNIQUE NOT NULL, malware_name TEXT, first_seen DATETIME, last_seen DATETIME, source TEXT, severity TEXT, tags TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS string_patterns (id INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT UNIQUE NOT NULL, description TEXT, malware_name TEXT, source TEXT, severity TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS yara_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_name TEXT UNIQUE NOT NULL, rule_content TEXT, author TEXT, description TEXT, created DATETIME, updated DATETIME, source TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS domain_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE NOT NULL, source TEXT, added DATETIME)''')
            conn.commit(); conn.close()
        except Exception as e:
            print(f"DB init error: {e}")

    def get_last_update(self) -> str:
        """Return last update as formatted string."""
        if self.last_update_file.exists():
            try:
                with open(self.last_update_file) as f: data = json.load(f)
                ts = data.get('timestamp')
                if ts:
                    dt = datetime.fromisoformat(ts)
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
            except: pass
        return 'Never'

    def get_last_update_datetime(self) -> Optional[datetime]:
        if self.last_update_file.exists():
            try:
                with open(self.last_update_file) as f: data = json.load(f)
                ts = data.get('timestamp')
                if ts: return datetime.fromisoformat(ts)
            except: pass
        return None

    def set_last_update(self, source=None, added=0, removed=0):
        data = {'timestamp':datetime.now().isoformat(),'source':source,'signatures_added':added,'signatures_removed':removed,'version':'2.0'}
        with open(self.last_update_file, 'w') as f: json.dump(data, f, indent=2)
        self.stats['last_successful'] = data['timestamp']; self.stats['total_updates'] += 1

    def check_for_updates(self) -> bool:
        last = self.get_last_update_datetime()
        if not last: return True
        return (datetime.now() - last).total_seconds() > self.config['check_interval']

    def get_signature_count(self) -> int:
        """Return total number of signatures as integer."""
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()
            total = 0
            for table in ['md5_signatures','sha256_signatures']:
                try: total += c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except: pass
            conn.close(); return total
        except: return 0

    def get_signature_count_detailed(self) -> Dict:
        """Return detailed signature count by type."""
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite))
            c = conn.cursor()
            counts = {}
            for table in ['md5_signatures','sha256_signatures','string_patterns','yara_rules']:
                try: counts[table] = c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except: counts[table] = 0
            conn.close(); return counts
        except: return {}

    def update_signatures(self, force: bool = False) -> Dict:
        if not REQUESTS_AVAILABLE:
            return {'success':False,'message':'requests library not installed','updated':False}
        if not force and not self.check_for_updates():
            return {'success':True,'message':'Signatures are up to date','updated':False}
        print("Checking for signature updates...")
        results = {'start_time':datetime.now().isoformat(),'sources_checked':0,'sources_updated':0,'total_signatures_added':0,'total_signatures_removed':0,'errors':[],'details':[]}
        enabled = sorted([s for s in self.update_sources if s.get('enabled',True)], key=lambda x: x.get('priority',999))
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['concurrent_downloads']) as ex:
            future_map = {ex.submit(self.download_from_source, src): src for src in enabled}
            for fut in concurrent.futures.as_completed(future_map):
                src = future_map[fut]; results['sources_checked'] += 1
                try:
                    content = fut.result(timeout=self.config['timeout']*2)
                    if content:
                        res = self.process_source_content(src, content)
                        if res['success']:
                            results['sources_updated'] += 1; results['total_signatures_added'] += res['added']
                            results['details'].append({'source':src['name'],'added':res['added'],'total':res.get('total',0)})
                        else: results['errors'].append({'source':src['name'],'error':res.get('error','Unknown')})
                except concurrent.futures.TimeoutError: results['errors'].append({'source':src['name'],'error':'Timeout'})
                except Exception as e: results['errors'].append({'source':src['name'],'error':str(e)})
        results['end_time'] = datetime.now().isoformat()
        s = datetime.fromisoformat(results['start_time']); e = datetime.fromisoformat(results['end_time'])
        results['duration'] = (e-s).total_seconds()
        if results['sources_updated'] > 0:
            results['success'] = True; results['message'] = f"Updated {results['sources_updated']} sources, added {results['total_signatures_added']} signatures"
            self.set_last_update(source=f"{results['sources_updated']} sources", added=results['total_signatures_added'])
            self.stats['signatures_count'] = self.get_signature_count()
        else:
            results['success'] = len(results['errors']) == 0; results['message'] = "No updates retrieved" if results['errors'] else "Sources checked, nothing new"
        return results

    def download_from_source(self, source: Dict) -> Optional[str]:
        if not REQUESTS_AVAILABLE: return None
        headers = {'User-Agent':'ZWYRM-AntiVirus/2.0','Accept':'text/plain,application/json','Accept-Encoding':'gzip, deflate'}
        for retry in range(self.config['max_retries']):
            try:
                print(f"  Downloading from {source['name']}...")
                r = requests.get(source['url'], headers=headers, timeout=self.config['timeout'], verify=self.config['verify_ssl'])
                r.raise_for_status(); print(f"    ✓ {len(r.content)} bytes"); return r.text
            except Exception as e:
                if retry == self.config['max_retries']-1: print(f"    ✗ {source['name']}: {e}")
                else: time.sleep(2**retry)
        return None

    def process_source_content(self, source: Dict, content: str) -> Dict:
        try:
            t = source['type']
            if t == 'md5': return self.process_md5_hashes(content, source['name'])
            elif t == 'sha256': return self.process_sha256_hashes(content, source['name'])
            elif t == 'vxdb': return self.process_vxdb_format(content, source['name'])
            elif t == 'domain': return self.process_domain_list(content, source['name'])
            elif t == 'json': return self.process_json_format(content, source['name'])
            else: return {'success':False,'error':f'Unknown type: {t}'}
        except Exception as e: return {'success':False,'error':str(e)}

    def process_md5_hashes(self, content: str, source_name: str) -> Dict:
        added = 0
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite)); c = conn.cursor()
            now = datetime.now().isoformat()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split('#',1); hash_val = parts[0].strip().lower()
                if len(hash_val) != 32: continue
                name = parts[1].strip() if len(parts) > 1 else 'Unknown'
                if not c.execute("SELECT id FROM md5_signatures WHERE hash=?",(hash_val,)).fetchone():
                    c.execute("INSERT INTO md5_signatures (hash,malware_name,first_seen,last_seen,source,severity,tags) VALUES (?,?,?,?,?,?,?)",(hash_val,name[:200],now,now,source_name,'medium',''))
                    added += 1
                else: c.execute("UPDATE md5_signatures SET last_seen=? WHERE hash=?",(now,hash_val))
            conn.commit(); total = c.execute("SELECT COUNT(*) FROM md5_signatures").fetchone()[0]; conn.close()
            return {'success':True,'added':added,'removed':0,'total':total}
        except Exception as e: return {'success':False,'error':str(e)}

    def process_sha256_hashes(self, content: str, source_name: str) -> Dict:
        added = 0
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite)); c = conn.cursor()
            now = datetime.now().isoformat()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split('#',1); hash_val = parts[0].strip().lower()
                if len(hash_val) != 64: continue
                name = parts[1].strip() if len(parts) > 1 else 'Unknown'
                if not c.execute("SELECT id FROM sha256_signatures WHERE hash=?",(hash_val,)).fetchone():
                    c.execute("INSERT INTO sha256_signatures (hash,malware_name,first_seen,last_seen,source,severity,tags) VALUES (?,?,?,?,?,?,?)",(hash_val,name[:200],now,now,source_name,'medium',''))
                    added += 1
            conn.commit(); total = c.execute("SELECT COUNT(*) FROM sha256_signatures").fetchone()[0]; conn.close()
            return {'success':True,'added':added,'removed':0,'total':total}
        except Exception as e: return {'success':False,'error':str(e)}

    def process_domain_list(self, content: str, source_name: str) -> Dict:
        added = 0
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite)); c = conn.cursor()
            try: c.execute("CREATE TABLE IF NOT EXISTS domain_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT UNIQUE NOT NULL, source TEXT, added DATETIME)")
            except: pass
            now = datetime.now().isoformat()
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('127.0.0.1') and len(line) < 15: continue
                parts = line.split(); domain = parts[-1] if len(parts) > 1 else parts[0]
                domain = domain.strip().lower()
                if '.' in domain and len(domain) > 3:
                    try: c.execute("INSERT OR IGNORE INTO domain_blacklist (domain,source,added) VALUES (?,?,?)",(domain,source_name,now)); added += c.rowcount
                    except: pass
            conn.commit(); conn.close()
            return {'success':True,'added':added,'removed':0,'total':added}
        except Exception as e: return {'success':False,'error':str(e)}

    def process_json_format(self, content: str, source_name: str) -> Dict:
        try:
            data = json.loads(content)
            added = 0
            conn = sqlite3.connect(str(self.signatures_sqlite)); c = conn.cursor()
            now = datetime.now().isoformat()
            for h in data.get('md5_hashes', []):
                if len(h) == 32:
                    if not c.execute("SELECT id FROM md5_signatures WHERE hash=?",(h,)).fetchone():
                        c.execute("INSERT INTO md5_signatures (hash,malware_name,first_seen,last_seen,source,severity,tags) VALUES (?,?,?,?,?,?,?)",(h,'Unknown',now,now,source_name,'medium',''))
                        added += 1
            for h in data.get('sha256_hashes', []):
                if len(h) == 64:
                    if not c.execute("SELECT id FROM sha256_signatures WHERE hash=?",(h,)).fetchone():
                        c.execute("INSERT INTO sha256_signatures (hash,malware_name,first_seen,last_seen,source,severity,tags) VALUES (?,?,?,?,?,?,?)",(h,'Unknown',now,now,source_name,'medium',''))
                        added += 1
            conn.commit(); conn.close()
            return {'success':True,'added':added,'removed':0,'total':added}
        except Exception as e: return {'success':False,'error':str(e)}

    def process_vxdb_format(self, content: str, source_name: str) -> Dict:
        added = 0
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite)); c = conn.cursor()
            now = datetime.now().isoformat(); current_name = None; current_md5 = None
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('Name:'): current_name = line[5:].strip()
                elif line.startswith('MD5:'): current_md5 = line[4:].strip().lower()
                    
            if current_md5 and current_name and len(current_md5) == 32:
                if not c.execute("SELECT id FROM md5_signatures WHERE hash=?",(current_md5,)).fetchone():
                    c.execute("INSERT INTO md5_signatures (hash,malware_name,first_seen,last_seen,source) VALUES (?,?,?,?,?)",(current_md5,current_name[:200],now,now,source_name))
                    added += 1
            conn.commit(); conn.close()
            return {'success':True,'added':added,'removed':0,'total':added}
        except Exception as e: return {'success':False,'error':str(e)}

    def notify_update(self, results: Dict):
        print(f"\n✅ Signatures updated: {results['total_signatures_added']} new")
        print(f"   Sources: {results['sources_updated']}/{results['sources_checked']}")
        print(f"   Duration: {results.get('duration',0):.1f}s")
        try:
            import subprocess; subprocess.run(['notify-send','ZWYRM Update',f"{results['total_signatures_added']} new signatures"],capture_output=True)
        except: pass

    def start_background_updater(self):
        if not self.config['enable_background_updates']: return
        def _loop():
            while True:
                try:
                    time.sleep(self.config['check_interval'])
                    if self.check_for_updates(): self.update_signatures()
                except KeyboardInterrupt: break
                except Exception as e: print(f"BG updater error: {e}"); time.sleep(60)
        t = threading.Thread(target=_loop, daemon=True); t.start()
        print("✓ Background updater started")

    def get_statistics(self) -> Dict:
        return {'total_updates':self.stats['total_updates'],'last_successful':self.stats['last_successful'],'signature_counts':self.get_signature_count_detailed(),'config':self.config}

    def cleanup_old_signatures(self, days_old: int = 90):
        try:
            conn = sqlite3.connect(str(self.signatures_sqlite)); c = conn.cursor()
            cutoff = (datetime.now()-timedelta(days=days_old)).isoformat()
            c.execute("DELETE FROM md5_signatures WHERE last_seen < ?",(cutoff,)); md5_r = c.rowcount
            c.execute("DELETE FROM sha256_signatures WHERE last_seen < ?",(cutoff,)); sha256_r = c.rowcount
            conn.commit(); conn.close()
            print(f"Cleaned up {md5_r} MD5 and {sha256_r} SHA256 signatures older than {days_old} days")
            return {'success':True,'md5_removed':md5_r,'sha256_removed':sha256_r}
        except Exception as e: return {'success':False,'error':str(e)}


# Backward-compatibility alias
SignatureUpdater = EnhancedSignatureUpdater
