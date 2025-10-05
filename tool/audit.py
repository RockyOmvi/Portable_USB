from __future__ import annotations
import json
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

try:
	from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
	from cryptography.hazmat.primitives import serialization
	_HAS_CRYPTO = True
except Exception:
	_HAS_CRYPTO = False


class AuditLogger:
	def __init__(self, audit_dir: Path) -> None:
		self.audit_dir = Path(audit_dir)
		self.audit_dir.mkdir(parents=True, exist_ok=True)
		self.log_file = self.audit_dir / "audit.jsonl"
		self.sig_file = self.audit_dir / "audit.sig"
		self._chain = self._load_chain()
		self._priv_file = self.audit_dir / "audit_ed25519_priv.pem"
		self._pub_file = self.audit_dir / "audit_ed25519_pub.pem"
		self._priv, self._pub = self._load_or_create_keys()

	def _load_chain(self) -> str:
		if self.sig_file.exists():
			return self.sig_file.read_text(encoding="utf-8").strip()
		return "0" * 64

	def _update_chain(self, record: Dict[str, Any]) -> str:
		payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
		sha = hashlib.sha256()
		sha.update(self._chain.encode("utf-8"))
		sha.update(payload)
		return sha.hexdigest()

	def _load_or_create_keys(self):
		if not _HAS_CRYPTO:
			return None, None
		if self._priv_file.exists() and self._pub_file.exists():
			priv = serialization.load_pem_private_key(self._priv_file.read_bytes(), password=None)
			pub = serialization.load_pem_public_key(self._pub_file.read_bytes())
			return priv, pub
		priv = Ed25519PrivateKey.generate()
		pub = priv.public_key()
		self._priv_file.write_bytes(
			priv.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)
		self._pub_file.write_bytes(
			pub.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo,
			)
		)
		return priv, pub

	def _sign(self, payload: bytes) -> str | None:
		if not _HAS_CRYPTO or self._priv is None:
			return None
		return base64.b64encode(self._priv.sign(payload)).decode("ascii")

	def verify_record(self, record: Dict[str, Any]) -> bool:
		if not _HAS_CRYPTO or self._pub is None:
			return False
		sig_b64 = record.get("sig")
		if not sig_b64:
			return False
		sig = base64.b64decode(sig_b64)
		# Remove signature for verification
		rec = dict(record)
		rec.pop("sig", None)
		payload = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")
		try:
			self._pub.verify(sig, payload)
			return True
		except Exception:
			return False

	def log_action(self, action: str, details: Dict[str, Any] | None = None) -> None:
		record = {
			"ts": datetime.utcnow().isoformat() + "Z",
			"action": action,
			"details": details or {},
		}
		new_chain = self._update_chain(record)
		record["chain"] = new_chain
		payload = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
		record["sig"] = self._sign(payload)
		with self.log_file.open("a", encoding="utf-8") as f:
			f.write(json.dumps(record, ensure_ascii=False) + "\n")
		self.sig_file.write_text(new_chain, encoding="utf-8")
		self._chain = new_chain
