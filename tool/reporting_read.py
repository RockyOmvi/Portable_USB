from __future__ import annotations
import base64
import json
from pathlib import Path
from typing import Dict, Any

from .crypto_utils import CryptoUtils, CryptoConfig


class ReportingManager:
	def __init__(self, usb_root: Path) -> None:
		self.usb_root = Path(usb_root)
		self.reports_dir = self.usb_root / "reports"
		self.keys_file = self.reports_dir / ".keys.json"
		self.crypto = self._load_crypto()

	def _load_crypto(self) -> CryptoUtils:
		data = json.loads(self.keys_file.read_text(encoding="utf-8"))
		enc = base64.b64decode(data["enc"]) 
		hmac = base64.b64decode(data["hmac"]) 
		old_enc = [base64.b64decode(x) for x in data.get("old_enc", [])]
		old_hmac = [base64.b64decode(x) for x in data.get("old_hmac", [])]
		return CryptoUtils(CryptoConfig(encryption_key=enc, hmac_key=hmac, old_encryption_keys=old_enc, old_hmac_keys=old_hmac))

	def decrypt_report(self, path: Path) -> Dict[str, Any]:
		payload = path.read_bytes()
		return self.crypto.decrypt_json_from_bytes(payload)
