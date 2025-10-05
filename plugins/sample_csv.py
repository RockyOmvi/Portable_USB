name = "sample_csv"

from pathlib import Path
from typing import Iterable, Dict, Any
import csv

def supports() -> Iterable[str]:
	return [".csv"]

def parse(path: Path) -> Iterable[Dict[str, Any]]:
	with path.open("r", encoding="utf-8", newline='') as f:
		reader = csv.DictReader(f)
		for row in reader:
			yield dict(row)
