from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Dict


def generate_manifest(root: Path, pattern: str = "report-*.json.enc") -> Path:
	root = Path(root)
	reports = sorted((root / "reports").glob(pattern))
	items: Dict[str, str] = {}
	for p in reports:
		data = p.read_bytes()
		h = hashlib.sha256(data).hexdigest()
		items[p.name] = h
	path = root / "reports" / "MANIFEST.sha256.json"
	path.write_text(json.dumps(items, indent=2), encoding="utf-8")
	return path


def verify_manifest(root: Path) -> bool:
	root = Path(root)
	path = root / "reports" / "MANIFEST.sha256.json"
	if not path.exists():
		return False
	items = json.loads(path.read_text(encoding="utf-8"))
	ok = True
	for name, digest in items.items():
		p = root / "reports" / name
		if not p.exists():
			ok = False
			continue
		h = hashlib.sha256(p.read_bytes()).hexdigest()
		ok = ok and (h == digest)
	return ok


