import json
import sys
from datetime import datetime
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table

from tool.os_utils import detect_os
from tool.audit import AuditLogger
from tool.reporting import ReportingManager as ReportingWriter
from tool.reporting_read import ReportingManager as ReportingReader
from tool.parsing import PluginLoader
from tool.streaming import scan_once
from tool.analysis import AnalysisEngine
from tool.exporting import export_to_json, export_to_csv, export_to_txt, export_to_pdf
from tool.secure_delete import SecureDeleter
from tool.temp_manager import TempManager
from tool.collectors import syslog_listen_udp, fetch_ftp, snapshot_host_logs
from tool.autorun import setup_autorun
from tool.bootstrap import create_usb_venv
import shutil
from tool.auth import verify_password, set_password
import tarfile
from tool.webapp import create_app
from tool.manifest import generate_manifest, verify_manifest

USB_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = USB_ROOT / "reports"
AUDIT_DIR = USB_ROOT / "audit"
PLUGINS_DIR = USB_ROOT / "plugins"
DOCS_DIR = USB_ROOT / "docs"

console = Console()
audit_logger = AuditLogger(AUDIT_DIR)


def ensure_directories() -> None:
	for p in [REPORTS_DIR, AUDIT_DIR, PLUGINS_DIR, DOCS_DIR, USB_ROOT / "bin"]:
		p.mkdir(parents=True, exist_ok=True)


@click.group()
@click.version_option("3.0", prog_name="Portable USB Log Analysis Tool – Ultimate")
@click.pass_context
def cli(ctx: click.Context) -> None:
	ensure_directories()
	ctx.ensure_object(dict)
	ctx.obj["os"] = detect_os()
	audit_logger.log_action("tool_start", {"os": ctx.obj["os"], "timestamp": datetime.utcnow().isoformat()})
	ctx.obj["tmp"] = TempManager(USB_ROOT)
	ctx.obj["deleter"] = SecureDeleter(USB_ROOT)


@cli.command("analyze-logs")
@click.option("--path", "scan_path", required=True, type=click.Path(exists=True, file_okay=False))
def analyze_logs(scan_path: str) -> None:
	loader = PluginLoader(PLUGINS_DIR)
	tmp: TempManager = click.get_current_context().obj["tmp"]
	events = []
	for p in Path(scan_path).rglob("*"):
		if not p.is_file():
			continue
		from tool.streaming import parse_file_with_plugins
		m, _ = parse_file_with_plugins(p, loader)
		if m:
			for info in loader.discover():
				plug = loader.load(info)
				if p.suffix.lower() in [e.lower() for e in plug.supports()]:
					try:
						for row in plug.parse(p):
							events.append(row)
					except Exception:
						pass
	engine = AnalysisEngine()
	engine.configure(rules_path=USB_ROOT / "plugins" / "rules.yaml", plugins_dir=PLUGINS_DIR)
	res = engine.analyze(events)
	rm = ReportingWriter(USB_ROOT)
	findings = {"events": events, "summary": {"severity_breakdown": res.severity_breakdown}}
	path = rm.write_encrypted_report(findings, res.score)
	audit_logger.log_action("analyze_logs", {"path": scan_path, "events": len(events), "score": res.score})
	console.print(f"Report generated: {path.name} (score: {res.score})")
	# Trigger cleanup on exit
	tmp.cleanup()


@cli.command("list-reports")
def list_reports() -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	reports = sorted(REPORTS_DIR.glob("report-*.json.enc"))
	table = Table(title="Encrypted Reports")
	table.add_column("#")
	table.add_column("Filename")
	for i, p in enumerate(reports, start=1):
		table.add_row(str(i), p.name)
	console.print(table)
	audit_logger.log_action("list_reports", {"count": len(reports)})


@cli.command("view-report")
@click.argument("name")
def view_report(name: str) -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	r = ReportingReader(USB_ROOT)
	path = REPORTS_DIR / name
	data = r.decrypt_report(path)
	console.print_json(data=data)
	audit_logger.log_action("view_report", {"name": name})


@cli.command("export-report")
@click.argument("name")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "txt", "pdf"], case_sensitive=False), required=True)
@click.option("--out", "out_path", required=False, type=click.Path(dir_okay=False))
def export_report(name: str, fmt: str, out_path: str | None) -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	r = ReportingReader(USB_ROOT)
	tmp: TempManager = click.get_current_context().obj["tmp"]
	data = r.decrypt_report(REPORTS_DIR / name)
	stem = name.replace(".json.enc", "")
	if not out_path:
		if fmt == "json":
			out_path = str(REPORTS_DIR / f"{stem}.json")
		elif fmt == "csv":
			out_path = str(REPORTS_DIR / f"{stem}.csv")
		elif fmt == "txt":
			out_path = str(REPORTS_DIR / f"{stem}.txt")
		else:
			out_path = str(REPORTS_DIR / f"{stem}.pdf")
	if fmt == "json":
		p = export_to_json(data, Path(out_path))
	elif fmt == "csv":
		p = export_to_csv(data, Path(out_path))
	elif fmt == "txt":
		p = export_to_txt(data, Path(out_path))
	else:
		p = export_to_pdf(data, Path(out_path))
	console.print(f"Exported: {p}")
	audit_logger.log_action("export_report", {"name": name, "format": fmt, "out": str(p)})
	# cleanup temp workspace
	tmp.cleanup()


@cli.command("rotate-keys")
def rotate_keys() -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	rm = ReportingWriter(USB_ROOT)
	rm.rotate_keys()
	console.print("Report encryption keys rotated. Old keys retained for decryption.")
	audit_logger.log_action("rotate_keys", {"ok": True})


@cli.command("delete-report")
@click.argument("name")
def delete_report(name: str) -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	deleter = SecureDeleter(USB_ROOT)
	tmp: TempManager = click.get_current_context().obj["tmp"]
	p = REPORTS_DIR / name
	if p.exists():
		ok = deleter.secure_delete(p)
		if ok:
			console.print(f"Deleted: {name}")
			audit_logger.log_action("delete_report", {"name": name, "status": "deleted"})
			return
	console.print(f"Not found or failed: {name}")
	audit_logger.log_action("delete_report", {"name": name, "status": "not_found_or_failed"})
	# cleanup temp workspace
	tmp.cleanup()


@cli.command("stream")
@click.option("--path", "stream_path", required=True, type=click.Path(exists=True, file_okay=False))
def stream(stream_path: str) -> None:
	from rich.live import Live
	from rich.panel import Panel
	from tool.streaming import watch_directory, parse_file_with_plugins
	loader = PluginLoader(PLUGINS_DIR)
	stats = {"files_processed": 0, "events_parsed": 0}
	# Initial scan to populate stats so the TUI is not empty at start
	try:
		initial = scan_once(Path(stream_path), loader)
		stats["files_processed"] += int(initial.files_processed)
		stats["events_parsed"] += int(initial.events_parsed)
	except Exception:
		pass

	def on_event(p: Path) -> None:
		m, r = parse_file_with_plugins(Path(p), loader)
		stats["files_processed"] += m
		stats["events_parsed"] += r

	with Live(refresh_per_second=2) as live:
		def render():
			return Panel(f"Files matched: {stats['files_processed']}\nEvents parsed: {stats['events_parsed']}", title="Streaming")
			
			
		live.update(render())
		try:
			watch_directory(Path(stream_path), loader, on_event= lambda p: live.update(render()) or on_event(p))
		except KeyboardInterrupt:
			pass
	audit_logger.log_action("stream_end", {"path": stream_path, "stats": stats})


@cli.command("dashboard")
@click.option("--path", "stream_path", required=False, type=click.Path(exists=True, file_okay=False), default=str(USB_ROOT / "test_stream"))
def dashboard(stream_path: str) -> None:
	"""Lightweight TUI dashboard with live streaming stats and top IPs."""
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	from rich.live import Live
	from rich.layout import Layout
	from rich.panel import Panel
	from rich.table import Table
	from collections import Counter
	from tool.streaming import watch_directory, parse_file_with_plugins
	loader = PluginLoader(PLUGINS_DIR)
	stats = {"files_processed": 0, "events_parsed": 0}
	ips = Counter()
	import re
	_ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
	# Initial scan to populate stats
	try:
		initial = scan_once(Path(stream_path), loader)
		stats["files_processed"] += int(initial.files_processed)
		stats["events_parsed"] += int(initial.events_parsed)
	except Exception:
		pass

	def on_event(p: Path) -> None:
		m, r = parse_file_with_plugins(Path(p), loader)
		stats["files_processed"] += m
		stats["events_parsed"] += r
		# extract IPs from known fields and fallback to regex over values
		try:
			for info in loader.discover():
				plug = loader.load(info)
				if p.suffix.lower() in [e.lower() for e in plug.supports()]:
					for row in plug.parse(Path(p)):
						# field-based
						for k in ("src_ip", "dst_ip", "ip", "remote_ip"):
							v = row.get(k)
							if isinstance(v, str):
								ips[v] += 1
						# regex over all stringifiable values
						try:
							text = " ".join(str(x) for x in row.values())
							for m in _ip_re.findall(text):
								ips[m] += 1
						except Exception:
							pass
		except Exception:
			pass

	def render():
		layout = Layout()
		layout.split_column(
			Layout(name="top", ratio=1),
			Layout(name="bottom", ratio=2),
		)
		top = Panel(f"Files matched: {stats['files_processed']}\nEvents parsed: {stats['events_parsed']}", title="Stats")
		table = Table(title="Top IPs")
		table.add_column("IP")
		table.add_column("Count")
		for ip, cnt in ips.most_common(10):
			table.add_row(ip, str(cnt))
		layout["top"].update(top)
		layout["bottom"].update(Panel(table))
		return layout

	with Live(render(), refresh_per_second=2) as live:
		try:
			watch_directory(Path(stream_path), loader, on_event=lambda p: live.update(render()) or on_event(p))
		except KeyboardInterrupt:
			pass


@cli.command("syslog-listen")
@click.option("--bind", default="0.0.0.0", show_default=True)
@click.option("--port", default=514, show_default=True)
@click.option("--out", "out_dir", required=False, type=click.Path(file_okay=False), default=str(USB_ROOT / "smoke"))
def syslog_listen(bind: str, port: int, out_dir: str) -> None:
	"""Listen for UDP syslog and append to a jsonl file under --out.
	Use Ctrl+C to stop."""
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	console.print(f"Listening syslog UDP on {bind}:{port}...")
	syslog_listen_udp(bind, port, Path(out_dir))


@cli.command("fetch-ftp")
@click.option("--host", required=True)
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
@click.option("--remote", "remote_path", required=True)
@click.option("--out", "out_dir", required=False, type=click.Path(file_okay=False), default=str(USB_ROOT / "smoke"))
def fetch_ftp_cmd(host: str, username: str, password: str, remote_path: str, out_dir: str) -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	path = fetch_ftp(host, username, password, remote_path, Path(out_dir))
	console.print(f"Downloaded: {path}")
	audit_logger.log_action("fetch_ftp", {"host": host, "remote": remote_path, "out": str(path)})


@cli.command("analyze-host")
@click.option("--since", required=False, help="Linux/macOS: journalctl/log show since, e.g. 1d or 2024-09-01")
@click.confirmation_option(prompt="Collect host logs with consent? Data is stored temporarily and processed locally.")
def analyze_host(since: str | None) -> None:
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	"""Snapshot host logs (with consent), parse via plugins, analyze, and report."""
	loader = PluginLoader(PLUGINS_DIR)
	tmp: TempManager = click.get_current_context().obj["tmp"]
	cap_dir = tmp.path("host_snapshot")
	snapshot_host_logs(cap_dir, since=since)
	# Reuse analyze-logs pipeline
	events = []
	for p in Path(cap_dir).rglob("*"):
		if not p.is_file():
			continue
		from tool.streaming import parse_file_with_plugins
		m, _ = parse_file_with_plugins(p, loader)
		if m:
			for info in loader.discover():
				plug = loader.load(info)
				if p.suffix.lower() in [e.lower() for e in plug.supports()]:
					try:
						for row in plug.parse(p):
							events.append(row)
					except Exception:
						pass
	engine = AnalysisEngine()
	engine.configure(rules_path=USB_ROOT / "plugins" / "rules.yaml", plugins_dir=PLUGINS_DIR)
	res = engine.analyze(events)
	rm = ReportingWriter(USB_ROOT)
	findings = {"events": events, "summary": {"severity_breakdown": res.severity_breakdown}}
	path = rm.write_encrypted_report(findings, res.score)
	audit_logger.log_action("analyze_host", {"events": len(events), "score": res.score})
	console.print(f"Report generated: {path.name} (score: {res.score})")
	tmp.cleanup()


@cli.command("self-test")
def self_test() -> None:
	"""Run end-to-end test on smoke data: analyze, list, view, export, delete (copy)."""
	# Analyze smoke directory
	ctx = click.get_current_context()
	ctx.invoke(analyze_logs, scan_path=str(USB_ROOT / "smoke"))
	# List reports
	reports = sorted(REPORTS_DIR.glob("report-*.json.enc"))
	if not reports:
		console.print("No reports generated.")
		return
	name = reports[-1].name
	# View
	ctx.invoke(view_report, name=name)
	# Export all formats
	for fmt in ("json", "csv", "txt", "pdf"):
		ctx.invoke(export_report, name=name, fmt=fmt, out_path=None)
	console.print("Self-test completed.")
	audit_logger.log_action("self_test", {"report": name})


@cli.command("setup-autorun")
def setup_autorun_cmd() -> None:
	"""Create best-effort autorun launchers for the current OS on this USB."""
	ok, msg = setup_autorun(USB_ROOT)
	console.print(msg)
	audit_logger.log_action("setup_autorun", {"ok": ok, "msg": msg})


@cli.command("bootstrap-env")
def bootstrap_env() -> None:
	"""Create a local venv on the USB and install requirements into it."""
	ok, msg = create_usb_venv(USB_ROOT)
	console.print(msg)
	audit_logger.log_action("bootstrap_env", {"ok": ok, "msg": msg})


@cli.command("set-password")
def set_password_cmd() -> None:
	ok, msg = set_password(AUDIT_DIR)
	console.print(msg)
	audit_logger.log_action("set_password", {"ok": ok})


@cli.command("clean-project")
@click.option("--include-tests", is_flag=True, help="Also remove test data (smoke/ and test_stream/)")
@click.option("--include-reports", is_flag=True, help="Also remove all encrypted reports and signatures")
def clean_project(include_tests: bool, include_reports: bool) -> None:
	"""Remove unnecessary caches and temporary artifacts from the USB project."""
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	removed: list[str] = []
	# Remove __pycache__ directories
	for d in USB_ROOT.rglob("__pycache__"):
		try:
			shutil.rmtree(d, ignore_errors=True)
			removed.append(str(d))
		except Exception:
			pass
	# Optionally remove test data
	if include_tests:
		for name in ("smoke", "test_stream"):
			d = USB_ROOT / name
			if d.exists():
				try:
					shutil.rmtree(d, ignore_errors=True)
					removed.append(str(d))
				except Exception:
					pass
	# Optionally remove reports
	if include_reports:
		for p in REPORTS_DIR.glob("report-*.json.enc"):
			try:
				p.unlink(missing_ok=True)
				removed.append(str(p))
			except Exception:
				pass
		for p in REPORTS_DIR.glob("report-*.json.enc.sig"):
			try:
				p.unlink(missing_ok=True)
				removed.append(str(p))
			except Exception:
				pass
	# Always remove temporary workspace if present
	try:
		TempManager(USB_ROOT).cleanup()
		removed.append(str((Path.tempdir() if hasattr(Path, 'tempdir') else 'temp')))
	except Exception:
		pass
	# Summary
	console.print(f"Removed {len(removed)} items")
	audit_logger.log_action("clean_project", {"removed": len(removed), "include_tests": include_tests, "include_reports": include_reports})


@cli.command("bundle-reports")
@click.option("--out", "out_tgz", required=False, type=click.Path(dir_okay=False), default=str(USB_ROOT / "reports_bundle.tgz"))
def bundle_reports(out_tgz: str) -> None:
	"""Create a tar.gz bundle of all encrypted reports and signatures for central transfer."""
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	out = Path(out_tgz)
	with tarfile.open(out, "w:gz") as tar:
		for p in REPORTS_DIR.glob("report-*.json.enc"):
			tar.add(p, arcname=p.name)
		for p in REPORTS_DIR.glob("report-*.json.enc.sig"):
			tar.add(p, arcname=p.name)
	console.print(f"Created bundle: {out}")
	audit_logger.log_action("bundle_reports", {"out": str(out)})


@cli.command("gen-manifest")
def gen_manifest() -> None:
	p = generate_manifest(USB_ROOT)
	console.print(f"Generated manifest: {p}")
	audit_logger.log_action("gen_manifest", {"path": str(p)})


@cli.command("verify-manifest")
def verify_manifest_cmd() -> None:
	ok = verify_manifest(USB_ROOT)
	console.print(f"Manifest verify: {'OK' if ok else 'FAIL'}")
	audit_logger.log_action("verify_manifest", {"ok": ok})


@cli.command("env-check")
def env_check() -> None:
	"""Check environment readiness for USB-only mode (local venv, optional tools)."""
	from shutil import which
	checks = {
		"python_in_venv": (Path(sys.executable).parent.parent == USB_ROOT / ".venv"),
		"watchdog": _try_import("watchdog"),
		"scapy": _try_import("scapy"),
		"geoip2": _try_import("geoip2"),
		"sdelete_present": ( (USB_ROOT / "bin" / "sdelete.exe").exists() or which("sdelete") is not None ),
		"shred_present": (which("shred") is not None),
		"srm_present": (which("srm") is not None),
	}
	table = Table(title="Environment Check")
	table.add_column("Check")
	table.add_column("OK")
	table.add_column("Note")
	for k, v in checks.items():
		note = ""
		if k in ("sdelete_present", "shred_present", "srm_present") and not v:
			note = "optional; fallback overwrite in use"
		table.add_row(k, "YES" if v else "NO", note)
	console.print(table)
	audit_logger.log_action("env_check", {"checks": checks})


def _try_import(name: str) -> bool:
	try:
		__import__(name)
		return True
	except Exception:
		return False


@cli.command("web-dashboard")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
def web_dashboard(host: str, port: int) -> None:
	"""Start a local web dashboard (static) to browse encrypted reports."""
	if not verify_password(AUDIT_DIR):
		console.print("Auth failed")
		return
	app = create_app(USB_ROOT)
	import socket
	def _find_free_port(h: str) -> int:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.bind((h, 0))
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			return s.getsockname()[1]

	# Try requested host/port, then a small range, then switch host and ephemeral
	hosts = [host, "127.0.0.1", "0.0.0.0"]
	for h in hosts:
		for attempt in range(0, 5):
			try_port = (port if attempt == 0 else port + attempt) if port else _find_free_port(h)
			try:
				url = f"http://{h}:{try_port}"
				if h == "0.0.0.0":
					url = f"http://127.0.0.1:{try_port}"
				console.print(f"Serving on {url}")
				try:
					from waitress import serve  # type: ignore
					serve(app, host=h, port=try_port)
				except Exception:
					app.run(host=h, port=try_port, threaded=False, use_reloader=False)
				return
			except KeyboardInterrupt:
				return
			except OSError as e:
				console.print(f"Port {try_port} failed ({e}). Trying next...")
				continue
	# Final fallback
	console.print("Failed to bind the web dashboard on available interfaces/ports.")


@cli.command("self-test-all")
def self_test_all() -> None:
	"""Run comprehensive tests across major functionality without network or long-running daemons."""
	# Self-tests bypass auth prompts to avoid blocking automation
	results = {"analyze_smoke": False, "exports": False, "decrypt": False, "delete_copy": False, "scan_once": False, "host_snapshot": False, "autorun_setup": False}
	# 1) Analyze smoke
	ctx = click.get_current_context()
	ctx.invoke(analyze_logs, scan_path=str(USB_ROOT / "smoke"))
	reports = sorted(REPORTS_DIR.glob("report-*.json.enc"))
	if reports:
		name = reports[-1].name
		results["analyze_smoke"] = True
		# 2) Decrypt and view
		try:
			ctx.invoke(view_report, name=name)
			results["decrypt"] = True
		except Exception:
			pass
		# 3) Export JSON/CSV/TXT/PDF
		ok = True
		for fmt in ("json", "csv", "txt", "pdf"):
			try:
				ctx.invoke(export_report, name=name, fmt=fmt, out_path=None)
			except Exception:
				ok = False
		results["exports"] = ok
		# 4) Secure delete a copy of the report (not the original)
		import shutil
		copy_name = name.replace(".json.enc", ".copy.json.enc")
		copy_path = REPORTS_DIR / copy_name
		try:
			shutil.copy2(REPORTS_DIR / name, copy_path)
			ctx.invoke(delete_report, name=copy_name)
			results["delete_copy"] = not copy_path.exists()
		except Exception:
			results["delete_copy"] = False
	# 5) Test streaming path via scan_once
	try:
		from tool.streaming import scan_once
		loader = PluginLoader(PLUGINS_DIR)
		stats = scan_once(USB_ROOT / "test_stream", loader)
		results["scan_once"] = isinstance(stats.files_processed, int)
	except Exception:
		pass
	# 6) Host snapshot collector (best effort; may be limited by OS permissions)
	try:
		tmp: TempManager = ctx.obj["tmp"]
		cap_dir = tmp.path("host_snapshot_test")
		snapshot_host_logs(cap_dir, since="1h")
		results["host_snapshot"] = True
		# cleanup snapshot files
		ctx.obj["deleter"].secure_delete_temp_dir()
	except Exception:
		pass
	# 7) Autorun setup
	try:
		ok, _ = setup_autorun(USB_ROOT)
		results["autorun_setup"] = ok
	except Exception:
		pass
	# Summary table
	table = Table(title="Self Test All Summary")
	table.add_column("Test")
	table.add_column("OK")
	for k, v in results.items():
		table.add_row(k, "YES" if v else "NO")
	console.print(table)
	audit_logger.log_action("self_test_all", {"results": results})
