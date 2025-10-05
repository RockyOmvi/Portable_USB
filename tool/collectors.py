from __future__ import annotations
import socket
import subprocess
from pathlib import Path
from typing import Optional

from .os_utils import detect_os


def syslog_listen_udp(bind: str, port: int, out_dir: Path) -> None:
	out_dir = Path(out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)
	outfile = out_dir / "syslog_udp.jsonl"
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((bind, port))
	try:
		while True:
			data, addr = sock.recvfrom(8192)
			line = data.decode("utf-8", errors="ignore").rstrip("\n")
			outfile.write_text("", encoding="utf-8") if not outfile.exists() else None
			with outfile.open("a", encoding="utf-8") as f:
				f.write('{"src":"%s","msg":%s}\n' % (addr[0], _json_escape(line)))
	finally:
		sock.close()


def _json_escape(s: str) -> str:
	return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def fetch_ftp(host: str, username: str, password: str, remote_path: str, out_dir: Path) -> Path:
	from ftplib import FTP
	out_dir = Path(out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)
	local = out_dir / Path(remote_path).name
	with FTP(host) as ftp:
		ftp.login(user=username, passwd=password)
		with local.open("wb") as f:
			ftp.retrbinary(f"RETR {remote_path}", f.write)
	return local


def snapshot_host_logs(out_dir: Path, since: Optional[str] = None) -> None:
	"""Export a minimal host log snapshot with explicit consent required by caller."""
	out_dir = Path(out_dir)
	out_dir.mkdir(parents=True, exist_ok=True)
	os = detect_os()
	if os == "Windows":
		# Export some key channels; requires admin for Security
		for chan in ["System", "Application"]:
			_dest = out_dir / f"{chan}.evtx"
			_run_silent(["wevtutil", "epl", chan, str(_dest)])
	elif os == "Linux":
		# Journalctl to text
		args = ["journalctl", "-o", "short-iso"]
		if since:
			args.extend(["--since", since])
		_dest = out_dir / "journalctl.txt"
		_run_to_file(args, _dest)
	else:
		# macOS unified logs
		args = ["log", "show", "--style", "syslog"]
		if since:
			args.extend(["--last", since])
		else:
			args.extend(["--last", "1d"])  # default
		_dest = out_dir / "macos_log_show.txt"
		_run_to_file(args, _dest)


def _run_silent(args: list[str]) -> None:
	try:
		subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
	except Exception:
		pass


def _run_to_file(args: list[str], out_file: Path) -> None:
	try:
		with out_file.open("wb") as f:
			subprocess.run(args, stdout=f, stderr=subprocess.DEVNULL, check=False)
	except Exception:
		pass


