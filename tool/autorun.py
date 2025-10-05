from __future__ import annotations
from pathlib import Path
from typing import Tuple

from .os_utils import detect_os


def setup_autorun(usb_root: Path) -> Tuple[bool, str]:
	"""Best-effort autorun scaffolding depending on OS security constraints.
	Returns (success, message)."""
	usb_root = Path(usb_root)
	os = detect_os()
	if os == "Windows":
		return _setup_windows(usb_root)
	if os == "Linux":
		return _setup_linux(usb_root)
	return _setup_macos(usb_root)


def _setup_windows(root: Path) -> Tuple[bool, str]:
	batch = root / "Run-PUTool.bat"
	batch.write_text("@echo off\r\nset VENV=%~dp0.venv\\Scripts\\python.exe\r\nif exist \"%VENV%\" (\r\n  \"%VENV%\" %~dp0bin\\putool.py list-reports\r\n) else (\r\n  python %~dp0bin\\putool.py list-reports\r\n)\r\npause\r\n", encoding="utf-8")
	autorun = root / "autorun.inf"
	autorun.write_text("[AutoRun]\r\nopen=Run-PUTool.bat\r\naction=Open Portable USB Log Analysis Tool\r\n", encoding="utf-8")
	return True, "Created autorun.inf and launcher .bat (may be ignored by Windows policy)"


def _setup_linux(root: Path) -> Tuple[bool, str]:
	launcher = root / "Run-PUTool.sh"
	launcher.write_text("#!/usr/bin/env bash\nPY=\"$(dirname \"$0\")/.venv/bin/python3\"\nif [ -x \"$PY\" ]; then \n  \"$PY\" \"$(dirname \"$0\")/bin/putool.py\" list-reports\nelse\n  python3 \"$(dirname \"$0\")/bin/putool.py\" list-reports\nfi\necho 'Press Enter to close'; read\n", encoding="utf-8")
	try:
		launcher.chmod(0o755)
	except Exception:
		pass
	desktop = root / "PUTool.desktop"
	desktop.write_text(
		"""[Desktop Entry]
Type=Application
Name=Portable USB Log Analysis Tool
Exec=sh -c '"$(dirname "%k")"/Run-PUTool.sh'
Icon=utilities-terminal
Terminal=true
""",
		encoding="utf-8",
	)
	return True, "Created .desktop and shell launcher (user may need to trust/run)"


def _setup_macos(root: Path) -> Tuple[bool, str]:
	cmd = root / "Run-PUTool.command"
	cmd.write_text("#!/bin/zsh\nPY=\"$(dirname $0)/.venv/bin/python3\"\nif [ -x \"$PY\" ]; then\n  \"$PY\" \"$(dirname $0)/bin/putool.py\" list-reports\nelse\n  python3 \"$(dirname $0)/bin/putool.py\" list-reports\nfi\necho 'Press Enter to close'; read\n", encoding="utf-8")
	try:
		cmd.chmod(0o755)
	except Exception:
		pass
	readme = root / "OPEN_ME_FIRST.txt"
	readme.write_text("Double-click Run-PUTool.command if it doesn't open automatically.", encoding="utf-8")
	return True, "Created .command launcher and instructions (Gatekeeper may prompt)"


