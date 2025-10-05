from __future__ import annotations
import os
import json
import secrets
import base64
import getpass
import hashlib
try:
	from argon2.low_level import hash_secret, Type
	_HAS_ARGON2 = True
except Exception:
	_HAS_ARGON2 = False
from pathlib import Path
from typing import Tuple


AUTH_FILE_NAME = ".auth.json"


def _derive(password: str, salt: bytes) -> bytes:
	if _HAS_ARGON2:
		return hash_secret(password.encode("utf-8"), salt, time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, type=Type.ID)
	return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def set_password(config_dir: Path, password: str | None = None) -> Tuple[bool, str]:
	config_dir = Path(config_dir)
	config_dir.mkdir(parents=True, exist_ok=True)
	path = config_dir / AUTH_FILE_NAME
	if password is None:
		password = getpass.getpass("Set password: ")
		confirm = getpass.getpass("Confirm password: ")
		if password != confirm:
			return False, "Passwords do not match"
	salt = os.urandom(16)
	dk = _derive(password, salt)
	data = {"salt": base64.b64encode(salt).decode("ascii"), "dk": base64.b64encode(dk).decode("ascii")}
	path.write_text(json.dumps(data), encoding="utf-8")
	return True, "Password set"


def verify_password(config_dir: Path, password: str | None = None) -> bool:
	path = Path(config_dir) / AUTH_FILE_NAME
	if not path.exists():
		return True
	if password is None:
		password = getpass.getpass("Password: ")
	try:
		data = json.loads(path.read_text(encoding="utf-8"))
		salt = base64.b64decode(data["salt"]) if isinstance(data.get("salt"), str) else b""
		dk = base64.b64decode(data["dk"]) if isinstance(data.get("dk"), str) else b""
		rec = _derive(password, salt)
		return secrets.compare_digest(rec, dk)
	except Exception:
		return False


