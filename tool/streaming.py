from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Iterable, List, Tuple

try:
	from watchdog.observers import Observer
	from watchdog.events import FileSystemEventHandler
	_HAS_WATCHDOG = True
except Exception:
	_HAS_WATCHDOG = False

from .parsing import PluginLoader
import time


@dataclass
class StreamStats:
	files_processed: int
	events_parsed: int


class _CreatedModifiedHandler(FileSystemEventHandler):  # type: ignore
	def __init__(self, callback):
		self.callback = callback

	def on_created(self, event):
		if not event.is_directory:
			self.callback(Path(event.src_path))

	def on_modified(self, event):
		if not event.is_directory:
			self.callback(Path(event.src_path))


def parse_file_with_plugins(path: Path, loader: PluginLoader) -> Tuple[int, int]:
	rows = 0
	matched = False
	ext = path.suffix.lower()
	for info in loader.discover():
		plugin = loader.load(info)
		if ext in [e.lower() for e in plugin.supports()]:  # type: ignore[attr-defined]
			matched = True
			try:
				for _ in plugin.parse(path):  # type: ignore[attr-defined]
					rows += 1
			except Exception:
				pass
	return int(matched), rows


def scan_once(root: Path, loader: PluginLoader) -> StreamStats:
	files = list(Path(root).rglob("*"))
	files = [p for p in files if p.is_file()]
	processed = 0
	events = 0
	for p in files:
		m, r = parse_file_with_plugins(p, loader)
		processed += m
		events += r
	return StreamStats(files_processed=processed, events_parsed=events)


def watch_directory(root: Path, loader: PluginLoader, on_event=None) -> None:
	if not _HAS_WATCHDOG:
		# Fallback to polling if watchdog not available
		return _poll_directory(root, loader, on_event)
	root = Path(root)
	root.mkdir(parents=True, exist_ok=True)
	def _cb(p: Path):
		parse_file_with_plugins(p, loader)
		if on_event:
			on_event(p)
	observer = Observer()
	handler = _CreatedModifiedHandler(_cb)
	observer.schedule(handler, str(root), recursive=True)
	try:
		observer.start()
		observer.join()
	except KeyboardInterrupt:
		observer.stop()
	except Exception:
		# Fallback to polling on runtime errors (e.g., threading incompatibilities)
		try:
			observer.stop()
		except Exception:
			pass
		return _poll_directory(root, loader, on_event)
	observer.stop()
	observer.join()


def _poll_directory(root: Path, loader: PluginLoader, on_event=None) -> None:
	root = Path(root)
	root.mkdir(parents=True, exist_ok=True)
	seen: Dict[Path, float] = {}
	try:
		while True:
			for p in root.rglob("*"):
				if not p.is_file():
					continue
				mt = p.stat().st_mtime
				prev = seen.get(p)
				if prev is None or mt > prev:
					seen[p] = mt
					parse_file_with_plugins(p, loader)
					if on_event:
						on_event(p)
			time.sleep(1.0)
	except KeyboardInterrupt:
		return
