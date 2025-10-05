name = "sample_syslog"

from pathlib import Path
from typing import Iterable, Dict, Any
import re

def supports() -> Iterable[str]:
	return [".log", ".syslog"]

_line = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$")

def parse(path: Path) -> Iterable[Dict[str, Any]]:
	with path.open("r", encoding="utf-8", errors='ignore') as f:
		for line in f:
			line = line.rstrip("\n")
			m = _line.match(line)
			if not m:
				continue
			yield m.groupdict()
