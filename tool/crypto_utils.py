from __future__ import annotations
import os
import json
import hmac
import hashlib
from dataclasses import dataclass
from typing import Tuple, List
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


@dataclass
class CryptoConfig:
	# Use separate keys for encryption and HMAC
	encryption_key: bytes
	hmac_key: bytes
	# Optional previous keys for rotation support
	old_encryption_keys: List[bytes] | None = None
	old_hmac_keys: List[bytes] | None = None


class CryptoUtils:
	TAG_LEN = 16
	NONCE_LEN = 12

	def __init__(self, config: CryptoConfig) -> None:
		if len(config.encryption_key) != 32:
			raise ValueError("encryption_key must be 32 bytes (AES-256)")
		if len(config.hmac_key) < 32:
			raise ValueError("hmac_key must be at least 32 bytes")
		self.cfg = config

	def encrypt_json_to_bytes(self, data: dict) -> bytes:
		plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
		nonce = get_random_bytes(self.NONCE_LEN)
		cipher = AES.new(self.cfg.encryption_key, AES.MODE_GCM, nonce=nonce, mac_len=self.TAG_LEN)
		ciphertext, tag = cipher.encrypt_and_digest(plaintext)
		blob = nonce + tag + ciphertext
		h = hmac.new(self.cfg.hmac_key, blob, hashlib.sha256).digest()
		return h + blob

	def decrypt_json_from_bytes(self, payload: bytes) -> dict:
		if len(payload) < 32 + self.NONCE_LEN + self.TAG_LEN:
			raise ValueError("payload too short")
		rec_hmac, rest = payload[:32], payload[32:]
		# Validate HMAC with primary or any old key
		keys = [self.cfg.hmac_key] + (self.cfg.old_hmac_keys or []) if getattr(self.cfg, 'old_hmac_keys', None) else [self.cfg.hmac_key]
		valid = False
		for k in keys:
			expected = hmac.new(k, rest, hashlib.sha256).digest()
			if hmac.compare_digest(rec_hmac, expected):
				valid = True
				break
		if not valid:
			raise ValueError("HMAC mismatch: possible tampering or wrong key")
		nonce = rest[:self.NONCE_LEN]
		tag = rest[self.NONCE_LEN:self.NONCE_LEN + self.TAG_LEN]
		ciphertext = rest[self.NONCE_LEN + self.TAG_LEN:]
		# Try primary then any old encryption key
		enc_keys = [self.cfg.encryption_key] + (self.cfg.old_encryption_keys or []) if getattr(self.cfg, 'old_encryption_keys', None) else [self.cfg.encryption_key]
		last_err = None
		for ek in enc_keys:
			try:
				cipher = AES.new(ek, AES.MODE_GCM, nonce=nonce, mac_len=self.TAG_LEN)
				plaintext = cipher.decrypt_and_verify(ciphertext, tag)
				return json.loads(plaintext.decode("utf-8"))
			except Exception as e:
				last_err = e
		raise ValueError(f"Decryption failed with all keys: {last_err}")
		return json.loads(plaintext.decode("utf-8"))

	@staticmethod
	def generate_keys() -> CryptoConfig:
		return CryptoConfig(encryption_key=get_random_bytes(32), hmac_key=get_random_bytes(32))
