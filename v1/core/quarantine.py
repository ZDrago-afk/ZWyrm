#!/usr/bin/env python3
# core/quarantine.py - Secure file quarantine with full CRUD

import os
import shutil
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class QuarantineManager:
    def __init__(self, quarantine_dir: str = None):
        if quarantine_dir:
            self.quarantine_dir = Path(quarantine_dir)
        else:
            # Try ~/.zwyrm/quarantine first, then local
            user_dir = Path.home() / '.zwyrm' / 'quarantine'
            local_dir = Path('quarantine')
            self.quarantine_dir = user_dir if user_dir.parent.exists() else local_dir

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.quarantine_dir / 'metadata.json'
        self.metadata = self._load_metadata()

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    def _load_metadata(self) -> Dict:
        """Load quarantine metadata from disk"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and 'items' in data:
                        return data
            except Exception:
                pass
        return {'items': [], 'next_id': 1}

    def _save_metadata(self):
        """Persist metadata to disk"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save quarantine metadata: {e}")

    def _next_id(self) -> int:
        """Get next available item ID"""
        if 'next_id' not in self.metadata:
            # Calculate from existing items
            ids = [i.get('id', 0) for i in self.metadata.get('items', [])]
            self.metadata['next_id'] = max(ids, default=0) + 1
        nid = self.metadata['next_id']
        self.metadata['next_id'] = nid + 1
        return nid

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def quarantine_file(self, filepath: str, threat_name: str = 'Unknown') -> int:
        """
        Move a file into quarantine.
        Returns the quarantine item ID (>0) on success, or -1 on failure.
        """
        try:
            src = Path(filepath)
            if not src.exists():
                return -1

            # Build unique quarantine filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_hash = hashlib.md5(str(src).encode()).hexdigest()[:8]
            q_name = f"{timestamp}_{file_hash}_{src.name}"
            q_path = self.quarantine_dir / q_name

            # Calculate hash before moving
            try:
                sha256 = hashlib.sha256()
                with open(src, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        sha256.update(chunk)
                file_sha256 = sha256.hexdigest()
            except Exception:
                file_sha256 = 'unknown'

            # Move the file
            shutil.move(str(src), str(q_path))

            # Record metadata
            item_id = self._next_id()
            item = {
                'id': item_id,
                'original_path': str(src),
                'quarantine_path': str(q_path),
                'filename': src.name,
                'threat_name': threat_name,
                'sha256': file_sha256,
                'quarantine_date': datetime.now().isoformat(),
                'size': q_path.stat().st_size if q_path.exists() else 0,
                'restored': False,
                'deleted': False,
            }
            self.metadata['items'].append(item)
            self._save_metadata()

            return item_id

        except Exception as e:
            print(f"Quarantine failed: {e}")
            return -1

    def restore(self, item_id: int) -> bool:
        """
        Restore a quarantined file to its original location.
        Returns True on success.
        """
        for item in self.metadata['items']:
            if item['id'] == item_id and not item.get('deleted', False):
                try:
                    src = Path(item['quarantine_path'])
                    dst = Path(item['original_path'])

                    if not src.exists():
                        print(f"Quarantine file not found: {src}")
                        return False

                    dst.parent.mkdir(parents=True, exist_ok=True)

                    if dst.exists():
                        # Avoid overwriting without asking — append suffix
                        dst = dst.with_name(dst.stem + '_restored' + dst.suffix)

                    shutil.move(str(src), str(dst))
                    item['restored'] = True
                    item['restore_date'] = datetime.now().isoformat()
                    item['restored_to'] = str(dst)
                    self._save_metadata()
                    return True

                except Exception as e:
                    print(f"Restore failed: {e}")
                    return False

        print(f"Item #{item_id} not found in quarantine")
        return False

    def delete(self, item_id: int) -> bool:
        """
        Permanently delete a quarantined file.
        Returns True on success.
        """
        for item in self.metadata['items']:
            if item['id'] == item_id:
                try:
                    q_path = Path(item['quarantine_path'])
                    if q_path.exists():
                        # Secure delete: overwrite with zeros before removing
                        try:
                            size = q_path.stat().st_size
                            if size > 0:
                                with open(q_path, 'wb') as f:
                                    f.write(b'\x00' * min(size, 1024 * 1024))
                        except Exception:
                            pass
                        q_path.unlink(missing_ok=True)

                    item['deleted'] = True
                    item['delete_date'] = datetime.now().isoformat()
                    self._save_metadata()
                    return True

                except Exception as e:
                    print(f"Delete failed: {e}")
                    return False

        print(f"Item #{item_id} not found in quarantine")
        return False

    def clear_all(self) -> int:
        """
        Permanently delete all quarantined files.
        Returns the number of files deleted.
        """
        count = 0
        for item in list(self.metadata['items']):
            if not item.get('deleted', False):
                if self.delete(item['id']):
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def list_quarantined(self) -> List[Dict]:
        """Return all active (non-deleted) quarantine items"""
        return [
            item for item in self.metadata.get('items', [])
            if not item.get('deleted', False) and not item.get('restored', False)
        ]

    def get_item(self, item_id: int) -> Optional[Dict]:
        """Get a single quarantine item by ID"""
        for item in self.metadata.get('items', []):
            if item['id'] == item_id:
                return item
        return None

    def count(self) -> int:
        """Count active quarantine items"""
        return len(self.list_quarantined())

    def get_quarantine_size(self) -> int:
        """Return total size of quarantined files in bytes"""
        total = 0
        for item in self.list_quarantined():
            q_path = Path(item.get('quarantine_path', ''))
            if q_path.exists():
                try:
                    total += q_path.stat().st_size
                except Exception:
                    pass
        return total

    def cleanup_old(self, days: int = 30) -> int:
        """Auto-delete quarantine items older than `days` days"""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=days)
        count = 0
        for item in list(self.metadata['items']):
            if item.get('deleted', False):
                continue
            try:
                q_date = datetime.fromisoformat(item.get('quarantine_date', ''))
                if q_date < cutoff:
                    if self.delete(item['id']):
                        count += 1
            except Exception:
                pass
        return count
