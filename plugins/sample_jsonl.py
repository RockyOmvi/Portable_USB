name = "sample_jsonl"

from pathlib import Path
from typing import Iterable, Dict, Any
import json

def supports() -> Iterable[str]:
	return [".jsonl"]

def parse(path: Path) -> Iterable[Dict[str, Any]]:
	with path.open("r", encoding="utf-8") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue
			yield json.loads(line)
