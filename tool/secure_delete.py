from __future__ import annotations
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from .os_utils import detect_os


class SecureDeleter:
	def __init__(self, usb_root: Optional[Path] = None) -> None:
		self.usb_root = Path(usb_root) if usb_root else Path(__file__).resolve().parents[1]
		self.platform = detect_os()

	def _run(self, args: Iterable[str]) -> bool:
		try:
			res = subprocess.run(list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
			return res.returncode == 0
		except Exception:
			return False

	def _windows_sdelete(self, target: Path) -> bool:
		sdelete = self._find_binary("sdelete.exe")
		if not sdelete:
			return False
		return self._run([str(sdelete), "-accepteula", "-q", str(target)])

	def _linux_shred(self, target: Path) -> bool:
		if not self._which("shred"):
			return False
		return self._run(["shred", "-uzn", "2", str(target)])

	def _macos_srm(self, target: Path) -> bool:
		if not self._which("srm"):
			return False
		return self._run(["srm", "-fzv", str(target)])

	def _which(self, name: str) -> Optional[str]:
		from shutil import which
		return which(name)

	def _find_binary(self, name: str) -> Optional[Path]:
		# Prefer USB bin first
		cand = self.usb_root / "bin" / name
		if cand.exists():
			return cand
		w = self._which(name)
		return Path(w) if w else None

	def secure_delete(self, target: Path) -> bool:
		target = Path(target)
		if not target.exists():
			return True
		ok = False
		if self.platform == "Windows":
			ok = self._windows_sdelete(target)
		elif self.platform == "macOS":
			ok = self._macos_srm(target)
		else:
			ok = self._linux_shred(target)
		if ok:
			return True
		# Fallback: overwrite then unlink
		try:
			if target.is_file():
				sz = target.stat().st_size or 4096
				with open(target, "r+b", buffering=0) as f:
					f.write(os.urandom(sz))
			target.unlink(missing_ok=True)
			return True
		except Exception:
			return False

	def secure_delete_temp_dir(self) -> bool:
		# Remove a safe temp workspace we might have used
		tmp = Path(tempfile.gettempdir()) / "putool_tmp"
		if not tmp.exists():
			return True
		ok = True
		for p in tmp.rglob("*"):
			if p.is_file():
				ok = self.secure_delete(p) and ok
		try:
			for p in sorted(tmp.rglob("*"), reverse=True):
				if p.is_dir():
					p.rmdir()
			tmp.rmdir()
		except Exception:
			pass
		return ok
