#!/usr/bin/env python3
# core/detector.py - Enhanced with ML and behavioral analysis

import re, math, json, hashlib
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

# Optional imports with graceful fallbacks
try:
    import numpy as np; NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import pefile; PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import lief; LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import magic; MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import pickle; PICKLE_AVAILABLE = True
except ImportError:
    PICKLE_AVAILABLE = False


class AdvancedAIDetector:
    def __init__(self):
        self.suspicious_strings = [
            "CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","NtCreateThreadEx",
            "SetWindowsHookEx","ShellExecute","WinExec","system","popen","CreateProcess",
            "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
            "socket","connect","send","recv","HttpSendRequest","InternetOpen","URLDownloadToFile",
            "RegCreateKey","RegSetValue","CreateService","StartService",
            "CryptEncrypt","CryptDecrypt","CryptGenKey","BCryptEncrypt",
            "VirtualAlloc","VirtualProtect","ReadProcessMemory","NtAllocateVirtualMemory",
            "eval(","exec(","compile(","__import__","execfile(","subprocess.Popen","os.system","pty.spawn"
        ]
        self.suspicious_imports = [
            "ws2_32.dll","wininet.dll","urlmon.dll","winhttp.dll",
            "CreateProcess","LoadLibrary","GetProcAddress","VirtualAlloc",
            "CreateService","RegCreateKey","NtCreateThreadEx","SetWindowsHookEx"
        ]
        self.feature_weights = {'entropy':0.25,'suspicious_strings':0.20,'suspicious_imports':0.15,'section_anomalies':0.15,'packer_indicators':0.10,'behavioral_patterns':0.15}
        self.entropy_threshold = 6.5
        self.section_entropy_threshold = 7.0
        self.packer_signatures = {
            b'UPX':'UPX',b'FSG!':'FSG',b'PECompact':'PECompact',b'ASPack':'ASPack',
            b'NsPacK':'NsPack',b'MPRESS':'MPRESS',b'VMProtect':'VMProtect',b'Themida':'Themida',b'ENIGMA':'ENIGMA'
        }
        self.behavioral_patterns = {
            'antidebug':['IsDebuggerPresent','CheckRemoteDebuggerPresent','OutputDebugString','NtQueryInformationProcess'],
            'antivm':['VMware','VirtualBox','VBox','QEMU','Xen','Hyper-V'],
            'persistence':['CreateService','RegCreateKey','Startup'],
            'network':['socket','connect','send','http://','https://'],
            'crypto':['Crypt','AES','RSA','RC4','DES'],
            'injection':['CreateRemoteThread','QueueUserAPC','SetWindowsHook']
        }
        self.ml_model = None
        self.vectorizer = None
        self.load_ml_model()

    def load_ml_model(self):
        if not PICKLE_AVAILABLE: return
        try:
            base = Path.home() / '.zwyrm'
            model_path = base / 'database' / 'ml_model.pkl'
            vec_path = base / 'database' / 'vectorizer.pkl'
            if model_path.exists() and vec_path.exists():
                import pickle
                with open(model_path,'rb') as f: self.ml_model = pickle.load(f)
                with open(vec_path,'rb') as f: self.vectorizer = pickle.load(f)
                print("✓ ML model loaded")
        except Exception as e:
            print(f"⚠ Could not load ML model: {e}")

    def calculate_entropy(self, data: bytes) -> float:
        if not data: return 0.0
        counter = Counter(data); total = len(data)
        return -sum((c/total)*math.log2(c/total) for c in counter.values() if c > 0)

    def detect_packed_executable(self, filepath: str) -> Dict:
        results = {'is_packed':False,'packer_name':None,'entropy':0.0,'sections':[],'indicators':[]}
        try:
            with open(filepath,'rb') as f: data = f.read(65536)
            entropy = self.calculate_entropy(data); results['entropy'] = entropy
            for sig, name in self.packer_signatures.items():
                if sig in data:
                    results['is_packed'] = True; results['packer_name'] = name
                    results['indicators'].append(f"Packer signature: {name}"); break
            if entropy > self.entropy_threshold and not results['is_packed']:
                results['is_packed'] = True; results['indicators'].append(f"High entropy: {entropy:.2f}")
            if PEFILE_AVAILABLE:
                try:
                    pe = pefile.PE(filepath)
                    for section in pe.sections:
                        sname = section.Name.decode(errors='ignore').strip('\x00')
                        sent = self.calculate_entropy(section.get_data())
                        results['sections'].append({'name':sname,'entropy':sent,'size':section.SizeOfRawData})
                        if sent > self.section_entropy_threshold:
                            results['is_packed'] = True; results['indicators'].append(f"High section entropy ({sname}): {sent:.2f}")
                    pe.close()
                except: pass
        except Exception as e: pass
        return results

    def analyze_strings(self, filepath: str) -> Dict:
        findings = {'suspicious_strings':[],'urls':[],'ips':[],'domains':[],'email_addresses':[],'file_paths':[],'registry_keys':[],'behavioral_patterns':defaultdict(list)}
        try:
            with open(filepath,'rb') as f: data = f.read(524288)
            for s_bytes in re.findall(b'[\x20-\x7E]{4,}', data):
                try: self._analyze_single_string(s_bytes.decode('ascii',errors='ignore'), findings)
                except: pass
        except: pass
        return findings

    def _analyze_single_string(self, string: str, findings: Dict):
        for s in self.suspicious_strings:
            if s.lower() in string.lower():
                findings['suspicious_strings'].append({'string':string[:100],'match':s,'severity':'high' if s in ['CreateRemoteThread','VirtualAllocEx'] else 'medium'})
        for pt, patterns in self.behavioral_patterns.items():
            for p in patterns:
                if p.lower() in string.lower():
                    findings['behavioral_patterns'][pt].append({'pattern':p,'string':string[:100]})
        findings['urls'].extend(re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.\-?=&%#]*', string))
        findings['ips'].extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', string))
        findings['registry_keys'].extend(re.findall(r'(HKEY_[A-Z_]+\\[^"\s]+|HK[A-Z]+\\[^"\s]+)', string, re.IGNORECASE))

    def analyze_pe_structure(self, filepath: str) -> Dict:
        findings = {'sections':[],'imports':[],'exports':[],'anomalies':[],'characteristics':{}}
        if not PEFILE_AVAILABLE: return findings
        try:
            pe = pefile.PE(filepath)
            findings['characteristics'] = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            }
            for section in pe.sections:
                sname = section.Name.decode(errors='ignore').strip('\x00')
                ent = self.calculate_entropy(section.get_data())
                sinfo = {'name':sname,'entropy':ent,'size':section.SizeOfRawData,'is_writable':bool(section.Characteristics & 0x80000000),'is_executable':bool(section.Characteristics & 0x20000000)}
                findings['sections'].append(sinfo)
                if sinfo['is_writable'] and sinfo['is_executable']:
                    findings['anomalies'].append({'type':'wx_section','section':sname,'description':'W^X violation','severity':'high'})
                if ent > self.section_entropy_threshold:
                    findings['anomalies'].append({'type':'high_entropy_section','section':sname,'entropy':ent,'description':'High entropy section','severity':'medium'})
            if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            iname = imp.name.decode(errors='ignore')
                            findings['imports'].append(f"{dll}!{iname}")
                            for s in self.suspicious_imports:
                                if s.lower() in iname.lower():
                                    findings['anomalies'].append({'type':'suspicious_import','import':f"{dll}!{iname}",'severity':'medium','description':'Suspicious API'})
            pe.close()
        except: pass
        return findings

    def behavioral_heuristics(self, filepath: str) -> Dict:
        findings = {'file_anomalies':[],'extension_analysis':[],'permission_analysis':[],'metadata_analysis':{}}
        try:
            import os, stat as stat_mod
            fp = Path(filepath)
            if MAGIC_AVAILABLE:
                try:
                    mime = magic.from_file(filepath, mime=True)
                    findings['metadata_analysis']['mime_type'] = mime
                    ext = fp.suffix.lower()
                    if ext in ['.exe','.dll'] and 'text' in mime:
                        findings['file_anomalies'].append({'type':'disguised_executable','description':f'Exec ext {ext} with text mime {mime}','severity':'high'})
                except: pass
            name = fp.name
            if name.count('.') > 1:
                double = ''.join(fp.suffixes[-2:]).lower()
                if any(double.endswith(e) for e in ['.exe','.bat','.cmd']):
                    findings['extension_analysis'].append({'type':'double_extension','filename':name,'description':'Double extension','severity':'medium'})
            if os.name == 'posix':
                st = os.stat(filepath); mode = stat_mod.S_IMODE(st.st_mode)
                if mode & stat_mod.S_ISUID: findings['permission_analysis'].append({'type':'setuid','mode':oct(mode),'severity':'medium','description':'setuid bit'})
                if mode & stat_mod.S_ISGID: findings['permission_analysis'].append({'type':'setgid','mode':oct(mode),'severity':'medium','description':'setgid bit'})
            size = os.path.getsize(filepath); findings['metadata_analysis']['size'] = size
            if size == 0: findings['file_anomalies'].append({'type':'zero_size','description':'Zero-byte file','severity':'low'})
        except: pass
        return findings

    def calculate_threat_score(self, findings: Dict) -> Tuple[float, str]:
        score = 0.0
        weights = {'high':5.0,'medium':3.0,'low':1.0}
        if findings.get('packer_analysis',{}).get('is_packed',False): score += 3.0
        score += len(findings.get('string_analysis',{}).get('suspicious_strings',[])) * 0.5
        for a in findings.get('pe_analysis',{}).get('anomalies',[]): score += weights.get(a.get('severity','low'),1.0)
        for a in findings.get('behavioral_analysis',{}).get('file_anomalies',[]): score += weights.get(a.get('severity','low'),1.0)
        for pt, patterns in findings.get('string_analysis',{}).get('behavioral_patterns',{}).items():
            mult = 2.0 if pt in ['antidebug','antivm','injection'] else 1.0
            score += len(patterns) * mult
        norm = min(100.0, score * 5.0)
        if norm >= 70: verdict = 'malicious'
        elif norm >= 40: verdict = 'suspicious'
        elif norm >= 20: verdict = 'potentially_unwanted'
        else: verdict = 'clean'
        return norm, verdict

    def analyze(self, filepath: str) -> Dict:
        results = {'filepath':filepath,'filename':Path(filepath).name,'timestamp':datetime.now().isoformat(),'analyses':{},'threat_score':0.0,'verdict':'unknown','threat_level':'unknown','indicators':[]}
        try:
            packer = self.detect_packed_executable(filepath)
            results['analyses']['packer_analysis'] = packer
            if packer['is_packed']: results['indicators'].extend(packer['indicators'])
            strings = self.analyze_strings(filepath)
            results['analyses']['string_analysis'] = strings
            pe = self.analyze_pe_structure(filepath)
            results['analyses']['pe_analysis'] = pe
            for a in pe.get('anomalies',[]): results['indicators'].append(f"PE: {a['description']}")
            beh = self.behavioral_heuristics(filepath)
            results['analyses']['behavioral_analysis'] = beh
            for a in beh.get('file_anomalies',[]): results['indicators'].append(f"Behavioral: {a['description']}")
            score, verdict = self.calculate_threat_score(results['analyses'])
            results['threat_score'] = score; results['verdict'] = verdict
            if score >= 70: results['threat_level'] = 'high'
            elif score >= 40: results['threat_level'] = 'medium'
            elif score >= 20: results['threat_level'] = 'low'
            else: results['threat_level'] = 'info'
        except Exception as e:
            results['error'] = str(e); results['verdict'] = 'error'
        return results

    def extract_ml_features(self, filepath: str, results: Dict) -> str:
        features = []
        for s in results['analyses'].get('string_analysis',{}).get('suspicious_strings',[]): features.append(f"str_{s['match'].lower()}")
        for a in results['analyses'].get('pe_analysis',{}).get('anomalies',[]): features.append(f"pe_{a['type']}")
        packer = results['analyses'].get('packer_analysis',{})
        if packer.get('is_packed',False):
            features.append("packed")
            if packer.get('packer_name'): features.append(f"packer_{packer['packer_name'].lower()}")
        return ' '.join(features)


# Backward-compatibility alias
EnhancedDetector = AdvancedAIDetector
