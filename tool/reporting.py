from __future__ import annotations
import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from .crypto_utils import CryptoUtils, CryptoConfig
try:
	from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
	from cryptography.hazmat.primitives import serialization
	_HAS_SIGNING = True
except Exception:
	_HAS_SIGNING = False


@dataclass
class ReportMeta:
	id: str
	created_utc: str
	severity: str
	format: str  # json


class ReportingManager:
	def __init__(self, usb_root: Path) -> None:
		self.usb_root = Path(usb_root)
		self.reports_dir = self.usb_root / "reports"
		self.reports_dir.mkdir(parents=True, exist_ok=True)
		self.keys_file = self.reports_dir / ".keys.json"
		self.crypto = CryptoUtils(self._load_or_create_keys())
		self._sign_priv = self._load_or_create_signing_key()

	def _load_or_create_keys(self) -> CryptoConfig:
		if self.keys_file.exists():
			data = json.loads(self.keys_file.read_text(encoding="utf-8"))
			enc = base64.b64decode(data["enc"]) 
			hmac = base64.b64decode(data["hmac"]) 
			old_enc = [base64.b64decode(x) for x in data.get("old_enc", [])]
			old_hmac = [base64.b64decode(x) for x in data.get("old_hmac", [])]
			return CryptoConfig(encryption_key=enc, hmac_key=hmac, old_encryption_keys=old_enc, old_hmac_keys=old_hmac)
		cfg = CryptoUtils.generate_keys()
		payload = {"enc": base64.b64encode(cfg.encryption_key).decode("ascii"), "hmac": base64.b64encode(cfg.hmac_key).decode("ascii")}
		self.keys_file.write_text(json.dumps(payload), encoding="utf-8")
		return cfg

	def rotate_keys(self) -> None:
		# Load current, push to old_*, generate new, and save
		if self.keys_file.exists():
			data = json.loads(self.keys_file.read_text(encoding="utf-8"))
			old_enc = data.get("old_enc", [])
			old_hmac = data.get("old_hmac", [])
			old_enc.insert(0, data["enc"])  # prepend current
			old_hmac.insert(0, data["hmac"])  # prepend current
			# cap history
			old_enc = old_enc[:5]
			old_hmac = old_hmac[:5]
			cfg = CryptoUtils.generate_keys()
			payload = {
				"enc": base64.b64encode(cfg.encryption_key).decode("ascii"),
				"hmac": base64.b64encode(cfg.hmac_key).decode("ascii"),
				"old_enc": old_enc,
				"old_hmac": old_hmac,
			}
			self.keys_file.write_text(json.dumps(payload), encoding="utf-8")
			self.crypto = CryptoUtils(self._load_or_create_keys())

	def _now_id(self) -> str:
		ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
		rand = os.urandom(4).hex()
		return f"{ts}-{rand}"

	def _load_or_create_signing_key(self):
		if not _HAS_SIGNING:
			return None
		priv_path = self.reports_dir / ".report_signing_ed25519_priv.pem"
		if priv_path.exists():
			return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
		priv = Ed25519PrivateKey.generate()
		priv_path.write_bytes(
			priv.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.NoEncryption(),
			)
		)
		return priv

	def _severity_for(self, score: int) -> str:
		if score >= 90:
			return "Critical"
		if score >= 70:
			return "High"
		if score >= 40:
			return "Medium"
		return "Low"

	def write_encrypted_report(self, findings: Dict[str, Any], score: int) -> Path:
		severity = self._severity_for(score)
		report_id = self._now_id()
		meta = ReportMeta(id=report_id, created_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), severity=severity, format="json")
		payload = {"meta": meta.__dict__, "findings": findings, "score": score}
		enc_bytes = self.crypto.encrypt_json_to_bytes(payload)
		fname = f"report-{meta.created_utc.replace(':','').replace('-','')[:15]}-{report_id.split('-')[-1]}.json.enc"
		path = self.reports_dir / fname
		path.write_bytes(enc_bytes)
		# Optional detached signature of encrypted payload
		if _HAS_SIGNING and self._sign_priv is not None:
			sig = self._sign_priv.sign(enc_bytes)
			(path.with_suffix(path.suffix + ".sig")).write_bytes(sig)
		return path
