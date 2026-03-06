#!/usr/bin/env python3
# core/quarantine.py
import os, shutil, json
from pathlib import Path
from datetime import datetime, timedelta
import hashlib

class QuarantineManager:
    def __init__(self):
        base = Path.home() / '.zwyrm'
        if base.exists():
            self.quarantine_dir = base / 'quarantine'
        else:
            self.quarantine_dir = Path('quarantine')
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.quarantine_dir / 'metadata.json'
        self.metadata = self.load_metadata()

    def load_metadata(self):
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file) as f: return json.load(f)
            except: pass
        return {'items': []}

    def save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2, default=str)

    def quarantine_file(self, filepath: str, threat_name: str = "Unknown") -> int:
        try:
            src = Path(filepath)
            if not src.exists(): return -1
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_hash = hashlib.md5(str(src).encode()).hexdigest()[:8]
            q_name = f"{timestamp}_{file_hash}_{src.name}"
            q_path = self.quarantine_dir / q_name
            shutil.move(str(src), str(q_path))
            item_id = max((i['id'] for i in self.metadata['items']), default=0) + 1
            self.metadata['items'].append({
                'id': item_id, 'original_path': str(src), 'quarantine_path': str(q_path),
                'filename': src.name, 'threat_name': threat_name,
                'quarantine_date': datetime.now().isoformat(), 'size': os.path.getsize(q_path)
            })
            self.save_metadata()
            return item_id
        except Exception as e:
            print(f"Quarantine failed: {e}"); return -1

    def restore(self, item_id: int) -> bool:
        for item in self.metadata['items']:
            if item['id'] == item_id:
                try:
                    src = Path(item['quarantine_path']); dst = Path(item['original_path'])
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dst))
                    self.metadata['items'] = [i for i in self.metadata['items'] if i['id'] != item_id]
                    self.save_metadata(); return True
                except Exception as e:
                    print(f"Restore failed: {e}"); return False
        return False

    def delete(self, item_id: int) -> bool:
        """Permanently delete a quarantined file (secure overwrite)."""
        for item in self.metadata['items']:
            if item['id'] == item_id:
                try:
                    q_path = Path(item['quarantine_path'])
                    if q_path.exists():
                        size = q_path.stat().st_size
                        if size > 0:
                            with open(q_path, 'wb') as f:
                                f.write(b'\x00' * min(size, 1024 * 1024))
                        q_path.unlink(missing_ok=True)
                    self.metadata['items'] = [i for i in self.metadata['items'] if i['id'] != item_id]
                    self.save_metadata(); return True
                except Exception as e:
                    print(f"Delete failed: {e}"); return False
        return False

    def clear_all(self) -> int:
        """Delete all quarantined files. Returns number removed."""
        count = 0
        for item in list(self.metadata['items']):
            if self.delete(item['id']): count += 1
        return count

    def get_quarantine_size(self) -> int:
        """Total bytes used by quarantine directory."""
        total = 0
        for item in self.metadata['items']:
            try: total += item.get('size', 0)
            except: pass
        return total

    def cleanup_old(self, days: int = 30) -> int:
        """Remove quarantined items older than N days. Returns count removed."""
        cutoff = datetime.now() - timedelta(days=days)
        count = 0
        for item in list(self.metadata['items']):
            try:
                qdate = datetime.fromisoformat(item['quarantine_date'])
                if qdate < cutoff:
                    if self.delete(item['id']): count += 1
            except: pass
        return count

    def list_quarantined(self): return self.metadata['items']
    def count(self): return len(self.metadata['items'])


# Backward-compatibility alias
EnhancedQuarantineManager = QuarantineManager
