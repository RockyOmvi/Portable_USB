from __future__ import annotations
import atexit
import tempfile
from pathlib import Path
from typing import Optional

from .secure_delete import SecureDeleter


class TempManager:
	def __init__(self, usb_root: Optional[Path] = None) -> None:
		self.usb_root = Path(usb_root) if usb_root else Path(__file__).resolve().parents[1]
		self.base = Path(tempfile.gettempdir()) / "putool_tmp"
		self.base.mkdir(parents=True, exist_ok=True)
		self.deleter = SecureDeleter(self.usb_root)
		atexit.register(self.cleanup)

	def path(self, *parts: str) -> Path:
		p = self.base.joinpath(*parts)
		p.parent.mkdir(parents=True, exist_ok=True)
		return p

	def cleanup(self) -> bool:
		return self.deleter.secure_delete_temp_dir()
