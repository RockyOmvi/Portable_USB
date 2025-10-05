from __future__ import annotations
import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Iterable, Dict, Any, List


class ParserPlugin(Protocol):
	name: str
	def supports(self) -> Iterable[str]: ...
	def parse(self, path: Path) -> Iterable[Dict[str, Any]]: ...


@dataclass
class PluginInfo:
	name: str
	path: Path


class PluginLoader:
	def __init__(self, plugins_dir: Path) -> None:
		self.plugins_dir = Path(plugins_dir)
		self.plugins_dir.mkdir(parents=True, exist_ok=True)

	def discover(self) -> List[PluginInfo]:
		infos: List[PluginInfo] = []
		for p in sorted(self.plugins_dir.glob("*.py")):
			if p.name.startswith("_"):
				continue
			infos.append(PluginInfo(name=p.stem, path=p))
		return infos

	def load(self, info: PluginInfo) -> ParserPlugin:
		spec = importlib.util.spec_from_file_location(info.name, str(info.path))
		if spec is None or spec.loader is None:
			raise RuntimeError(f"Unable to load plugin {info.name}")
		mod = importlib.util.module_from_spec(spec)
		spec.loader.exec_module(mod)  # type: ignore
		# Simple validation
		for attr in ("name", "supports", "parse"):
			if not hasattr(mod, attr):
				raise RuntimeError(f"Plugin {info.name} missing attribute: {attr}")
		return mod  # type: ignore
