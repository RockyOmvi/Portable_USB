from __future__ import annotations
import subprocess
import sys
from pathlib import Path
from typing import Tuple


def create_usb_venv(usb_root: Path) -> Tuple[bool, str]:
	usb_root = Path(usb_root)
	venv_dir = usb_root / ".venv"
	python_exe = venv_dir / ("Scripts" if sys.platform.startswith("win") else "bin") / ("python.exe" if sys.platform.startswith("win") else "python3")
	if python_exe.exists():
		ok, msg = _install_requirements(python_exe, usb_root)
		return ok, f"Venv already present. {_short(msg)}"
	# Create venv
	try:
		subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
	except Exception as e:
		return False, f"Failed to create venv: {e}"
	# Install requirements
	return _install_requirements(python_exe, usb_root)


def _install_requirements(python_exe: Path, usb_root: Path) -> Tuple[bool, str]:
	req = usb_root / "requirements.txt"
	vendor = usb_root / "vendor"
	cmd = [str(python_exe), "-m", "pip", "install", "-U", "pip", "setuptools", "wheel"]
	try:
		subprocess.run(cmd, check=False)
	except Exception:
		pass
	cmd = [str(python_exe), "-m", "pip", "install", "-r", str(req)]
	if vendor.exists():
		cmd.extend(["--no-index", "--find-links", str(vendor)])
	try:
		res = subprocess.run(cmd, check=False, capture_output=True, text=True)
		ok = res.returncode == 0
		return ok, (res.stdout[-500:] + res.stderr[-500:])
	except Exception as e:
		return False, f"pip failed: {e}"


def _short(s: str) -> str:
	return s[-200:] if s else ""


