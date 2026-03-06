#!/usr/bin/env python3
# core/detector.py - Advanced detection with graceful optional dependency handling

import re
import math
import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

# Optional imports with graceful fallback
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import magic as libmagic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import pickle
    import sklearn
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class AdvancedAIDetector:
    def __init__(self):
        self.suspicious_strings = [
            # System manipulation
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
            # Code injection
            "SetWindowsHookEx", "SetWinEventHook", "CreateTimerQueueTimer",
            # Execution
            "ShellExecute", "WinExec", "system", "popen", "CreateProcess",
            # Evasion
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString",
            # Network
            "socket", "connect", "send", "recv", "bind", "listen",
            "HttpSendRequest", "InternetOpen", "URLDownloadToFile",
            # Persistence
            "RegCreateKey", "RegSetValue", "CreateService", "StartService",
            # Scripting
            "eval(", "exec(", "compile(", "__import__", "execfile(",
            "subprocess.Popen", "os.system", "pty.spawn",
        ]

        self.packer_signatures = {
            b'UPX': 'UPX', b'FSG!': 'FSG', b'PECompact': 'PECompact',
            b'ASPack': 'ASPack', b'NsPacK': 'NsPack', b'RLPack': 'RLPack',
            b'MPRESS': 'MPRESS', b'Petite': 'Petite', b'UPack': 'UPack',
            b'VMProtect': 'VMProtect', b'Themida': 'Themida',
            b'Obsidium': 'Obsidium', b'ENIGMA': 'ENIGMA',
        }

        self.behavioral_patterns = {
            'antidebug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                          'OutputDebugString', 'NtQueryInformationProcess'],
            'antivm': ['VMware', 'VirtualBox', 'VBox', 'QEMU', 'Xen', 'Hyper-V'],
            'persistence': ['CreateService', 'RegCreateKey', 'Startup'],
            'network': ['socket', 'connect', 'send', 'http://', 'https://'],
            'crypto': ['Crypt', 'AES', 'RSA', 'RC4', 'DES'],
            'injection': ['CreateRemoteThread', 'QueueUserAPC', 'SetWindowsHook'],
        }

        self.entropy_threshold = 6.5
        self.section_entropy_threshold = 7.0

        # ML model (optional)
        self.ml_model = None
        self.vectorizer = None
        self._load_ml_model()

    def _load_ml_model(self):
        """Load trained ML model if available"""
        if not SKLEARN_AVAILABLE:
            return

        model_path = Path('database/ml_model.pkl')
        vec_path = Path('database/vectorizer.pkl')

        if model_path.exists() and vec_path.exists():
            try:
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                with open(vec_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Entropy
    # ------------------------------------------------------------------

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        counter = Counter(data)
        total = len(data)
        entropy = 0.0

        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    # ------------------------------------------------------------------
    # Packer detection
    # ------------------------------------------------------------------

    def detect_packed_executable(self, filepath: str) -> Dict:
        """Detect packed/obfuscated executables"""
        results = {
            'is_packed': False,
            'packer_name': None,
            'entropy': 0.0,
            'sections': [],
            'indicators': []
        }

        try:
            with open(filepath, 'rb') as f:
                data = f.read(65536)

            entropy = self.calculate_entropy(data)
            results['entropy'] = entropy

            # Check packer signatures
            for signature, name in self.packer_signatures.items():
                if signature in data:
                    results['is_packed'] = True
                    results['packer_name'] = name
                    results['indicators'].append(f'Packer signature: {name}')
                    break

            if entropy > self.entropy_threshold and not results['is_packed']:
                results['is_packed'] = True
                results['indicators'].append(f'High entropy: {entropy:.2f}')

            # PE section analysis
            if PEFILE_AVAILABLE:
                try:
                    pe = pefile.PE(filepath, fast_load=True)
                    for section in pe.sections:
                        sec_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                        sec_data = section.get_data()
                        sec_entropy = self.calculate_entropy(sec_data)
                        results['sections'].append({
                            'name': sec_name,
                            'entropy': sec_entropy,
                            'size': section.SizeOfRawData,
                        })
                        if sec_entropy > self.section_entropy_threshold:
                            results['is_packed'] = True
                            results['indicators'].append(
                                f'High section entropy ({sec_name}): {sec_entropy:.2f}')
                    pe.close()
                except Exception:
                    pass

        except Exception:
            pass

        return results

    # ------------------------------------------------------------------
    # String analysis
    # ------------------------------------------------------------------

    def analyze_strings(self, filepath: str) -> Dict:
        """Advanced string analysis"""
        findings: Dict[str, Any] = {
            'suspicious_strings': [],
            'urls': [],
            'ips': [],
            'domains': [],
            'email_addresses': [],
            'file_paths': [],
            'registry_keys': [],
            'behavioral_patterns': defaultdict(list)
        }

        try:
            with open(filepath, 'rb') as f:
                data = f.read(524288)  # 512KB

            # ASCII strings
            for s_bytes in re.findall(rb'[\x20-\x7E]{4,}', data):
                try:
                    s = s_bytes.decode('ascii', errors='ignore')
                    self._analyze_single_string(s, findings)
                except Exception:
                    pass

            # Unicode strings (UTF-16 LE)
            for s_bytes in re.findall(rb'(?:[\x20-\x7E]\x00){4,}', data):
                try:
                    s = s_bytes.decode('utf-16-le', errors='ignore')
                    self._analyze_single_string(s, findings)
                except Exception:
                    pass

        except Exception:
            pass

        return findings

    def _analyze_single_string(self, string: str, findings: Dict):
        """Analyze a single string for IOCs"""
        # Suspicious API strings
        for susp in self.suspicious_strings:
            if susp.lower() in string.lower():
                existing = [x['match'] for x in findings['suspicious_strings']]
                if susp not in existing:
                    findings['suspicious_strings'].append({
                        'string': string[:100],
                        'match': susp,
                        'severity': 'high' if susp in ['CreateRemoteThread', 'VirtualAllocEx'] else 'medium'
                    })

        # Behavioral patterns
        for ptype, patterns in self.behavioral_patterns.items():
            for pattern in patterns:
                if pattern.lower() in string.lower():
                    findings['behavioral_patterns'][ptype].append({
                        'pattern': pattern,
                        'string': string[:100]
                    })

        # URLs
        for url in re.findall(r'https?://[^\s"\'<>]{4,}', string):
            if url not in findings['urls']:
                findings['urls'].append(url)

        # IP addresses
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', string):
            if ip not in findings['ips']:
                findings['ips'].append(ip)

        # Email addresses
        for email in re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', string):
            if email not in findings['email_addresses']:
                findings['email_addresses'].append(email)

        # Registry keys
        for rkey in re.findall(r'(HKEY_[A-Z_]+\\[^\s"]+|HK[A-Z]+\\[^\s"]+)', string, re.IGNORECASE):
            if rkey not in findings['registry_keys']:
                findings['registry_keys'].append(rkey)

    # ------------------------------------------------------------------
    # PE analysis
    # ------------------------------------------------------------------

    def analyze_pe_structure(self, filepath: str) -> Dict:
        """PE file structure analysis"""
        findings: Dict[str, Any] = {
            'sections': [],
            'imports': [],
            'exports': [],
            'anomalies': [],
            'characteristics': {}
        }

        if not PEFILE_AVAILABLE:
            return findings

        try:
            pe = pefile.PE(filepath)

            findings['characteristics'] = {
                'machine': hex(pe.FILE_HEADER.Machine),
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            }

            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                sec_data = section.get_data()
                entropy = self.calculate_entropy(sec_data)
                is_wx = bool(section.Characteristics & 0x80000000) and \
                        bool(section.Characteristics & 0x20000000)

                findings['sections'].append({
                    'name': sec_name,
                    'entropy': entropy,
                    'raw_size': section.SizeOfRawData,
                    'is_wx': is_wx,
                })

                if is_wx:
                    findings['anomalies'].append({
                        'type': 'wx_section',
                        'section': sec_name,
                        'description': 'W^X violation: section is writable and executable',
                        'severity': 'high'
                    })
                if entropy > self.section_entropy_threshold:
                    findings['anomalies'].append({
                        'type': 'high_entropy_section',
                        'section': sec_name,
                        'entropy': entropy,
                        'description': f'High entropy section: {entropy:.2f}',
                        'severity': 'medium'
                    })

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            findings['imports'].append(f"{dll_name}!{imp.name.decode('utf-8', errors='ignore')}")

            pe.close()

        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # Behavioral heuristics
    # ------------------------------------------------------------------

    def behavioral_heuristics(self, filepath: str) -> Dict:
        """File-level behavioral heuristics"""
        findings: Dict[str, Any] = {
            'file_anomalies': [],
            'extension_analysis': [],
            'permission_analysis': [],
            'metadata_analysis': {}
        }

        try:
            fp = Path(filepath)
            file_size = os.path.getsize(filepath) if hasattr(os, 'path') else fp.stat().st_size

            findings['metadata_analysis']['size'] = file_size

            if MAGIC_AVAILABLE:
                try:
                    mime = libmagic.from_file(filepath, mime=True)
                    findings['metadata_analysis']['mime_type'] = mime
                    findings['metadata_analysis']['file_type'] = libmagic.from_file(filepath)
                except Exception:
                    pass

            # Double extension
            if fp.name.count('.') > 1:
                double_ext = ''.join(fp.suffixes[-2:]).lower()
                if any(double_ext.endswith(x) for x in ['.exe', '.bat', '.cmd', '.vbs']):
                    findings['extension_analysis'].append({
                        'type': 'double_extension',
                        'filename': fp.name,
                        'description': 'Double extension may be hiding true type',
                        'severity': 'medium'
                    })

            # Permissions (Linux)
            if os.name == 'posix':
                import stat
                st = os.stat(filepath)
                mode = stat.S_IMODE(st.st_mode)
                if mode & stat.S_ISUID:
                    findings['permission_analysis'].append({
                        'type': 'setuid', 'mode': oct(mode),
                        'description': 'Setuid bit set', 'severity': 'medium'
                    })
                if mode & stat.S_ISGID:
                    findings['permission_analysis'].append({
                        'type': 'setgid', 'mode': oct(mode),
                        'description': 'Setgid bit set', 'severity': 'medium'
                    })

        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # Threat scoring
    # ------------------------------------------------------------------

    def calculate_threat_score(self, findings: Dict) -> Tuple[float, str]:
        """Calculate overall threat score"""
        score = 0.0
        weight = {'high': 5.0, 'medium': 3.0, 'low': 1.0}

        if findings.get('packer_analysis', {}).get('is_packed', False):
            score += 3.0

        susp_strings = findings.get('string_analysis', {}).get('suspicious_strings', [])
        score += len(susp_strings) * 0.5

        for anomaly in findings.get('pe_analysis', {}).get('anomalies', []):
            score += weight.get(anomaly.get('severity', 'low'), 1.0)

        for anomaly in findings.get('behavioral_analysis', {}).get('file_anomalies', []):
            score += weight.get(anomaly.get('severity', 'low'), 1.0)

        bpatterns = findings.get('string_analysis', {}).get('behavioral_patterns', {})
        for ptype, patterns in bpatterns.items():
            mult = 2.0 if ptype in ['antidebug', 'antivm', 'injection'] else 1.0
            score += len(patterns) * mult

        normalized = min(100.0, score * 5.0)

        if normalized >= 70:
            verdict = 'malicious'
        elif normalized >= 40:
            verdict = 'suspicious'
        elif normalized >= 20:
            verdict = 'potentially_unwanted'
        else:
            verdict = 'clean'

        return normalized, verdict

    # ------------------------------------------------------------------
    # Full analysis entry point
    # ------------------------------------------------------------------

    def analyze(self, filepath: str) -> Dict:
        """Run all detection modules on a file"""
        results: Dict[str, Any] = {
            'filepath': filepath,
            'filename': Path(filepath).name,
            'timestamp': datetime.now().isoformat(),
            'analyses': {},
            'threat_score': 0.0,
            'verdict': 'unknown',
            'threat_level': 'unknown',
            'indicators': []
        }

        try:
            packer = self.detect_packed_executable(filepath)
            results['analyses']['packer_analysis'] = packer
            if packer['is_packed']:
                results['indicators'].extend(packer['indicators'])

            strings = self.analyze_strings(filepath)
            results['analyses']['string_analysis'] = strings

            pe = self.analyze_pe_structure(filepath)
            results['analyses']['pe_analysis'] = pe
            for a in pe.get('anomalies', []):
                results['indicators'].append(f"PE: {a['description']}")

            behavioral = self.behavioral_heuristics(filepath)
            results['analyses']['behavioral_analysis'] = behavioral
            for a in behavioral.get('file_anomalies', []):
                results['indicators'].append(f"Behavioral: {a['description']}")

            score, verdict = self.calculate_threat_score(results['analyses'])
            results['threat_score'] = score
            results['verdict'] = verdict

            if score >= 70:
                results['threat_level'] = 'high'
            elif score >= 40:
                results['threat_level'] = 'medium'
            elif score >= 20:
                results['threat_level'] = 'low'
            else:
                results['threat_level'] = 'info'

        except Exception as e:
            results['error'] = str(e)
            results['verdict'] = 'error'

        return results


import os  # ensure os is available at module level
