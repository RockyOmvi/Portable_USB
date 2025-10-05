name = "txt_plain"

from pathlib import Path
from typing import Iterable, Dict, Any


def supports() -> Iterable[str]:
	return [".txt"]


def parse(path: Path) -> Iterable[Dict[str, Any]]:
	with path.open("r", encoding="utf-8", errors="ignore") as f:
		for i, line in enumerate(f, start=1):
			line = line.rstrip("\n")
			if not line:
				continue
			yield {"line": line, "line_no": i}


