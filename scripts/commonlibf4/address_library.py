"""Fallout 4 address library loader (libxse/commonlibf4 format).

Binary format (from CommonLibF4 IDDatabase::load()):
  uint64  count
  count x (uint64 id, uint64 offset) pairs, sorted by id

Only the AE (1.11.191) database is used.  ``REL::ID``/``RELOCATION_ID``
relocations from libxse refer to AE offsets, and the IDA fallback names
in ``extras/IDAImportNames_1.11.191.0.py`` are already AE-keyed, so no
cross-version rebase is needed.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Optional


class F4AddressLibrary:
    """Loads the AE (1.11.191) Fallout 4 address library .bin file."""

    def __init__(self):
        self.ae_db: Dict[int, int] = {}

    def load_bin(self, file_path: str) -> Dict[int, int]:
        if not os.path.exists(file_path):
            return {}
        db = {}
        with open(file_path, 'rb') as f:
            count = struct.unpack('<Q', f.read(8))[0]
            for _ in range(count):
                id_, offset = struct.unpack('<QQ', f.read(16))
                db[id_] = offset
        return db

    def load_all(self, base_path: str) -> None:
        self.ae_db = self.load_bin(os.path.join(base_path, 'version-1-11-191-0.bin'))

    def get_ae(self, id_: int) -> Optional[int]:
        return self.ae_db.get(id_) if id_ else None
