from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any
from pathlib import Path
import ipaddress
import json


@dataclass
class ThreatIntel:
	malicious_ips: List[str]
	malicious_domains: List[str]
	malicious_hashes: List[str]


def load_feeds(plugins_dir: Path) -> ThreatIntel:
	plugins_dir = Path(plugins_dir)
	ip_file = plugins_dir / "ti_ips.txt"
	dom_file = plugins_dir / "ti_domains.txt"
	hash_file = plugins_dir / "ti_hashes.txt"
	ti = ThreatIntel(
		malicious_ips=_read_lines(ip_file),
		malicious_domains=_read_lines(dom_file),
		malicious_hashes=_read_lines(hash_file),
	)
	# Merge STIX if present
	for stix_path in sorted(plugins_dir.glob("*.stix.json")):
		try:
			stix = json.loads(stix_path.read_text(encoding="utf-8"))
			_parse_stix_into(ti, stix)
		except Exception:
			continue
	return ti


def _read_lines(path: Path) -> List[str]:
	if not path.exists():
		return []
	return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def is_malicious_ip(ti: ThreatIntel, value: str) -> bool:
	try:
		ipaddress.ip_address(value)
	except Exception:
		return False
	return value in set(ti.malicious_ips)


def _parse_stix_into(ti: ThreatIntel, bundle: Dict[str, Any]) -> None:
	objects = bundle.get("objects") or []
	for obj in objects:
		type_ = obj.get("type")
		if type_ == "indicator":
			pattern = obj.get("pattern", "")
			if "ipv4-addr:value" in pattern or "ipv6-addr:value" in pattern:
				for token in pattern.replace("'", " ").replace("[", " ").replace("]", " ").split():
					if token.count(".") == 3 or ":" in token:
						try:
							ipaddress.ip_address(token)
							ti.malicious_ips.append(token)
						except Exception:
							pass
			elif "domain-name:value" in pattern:
				for token in pattern.replace("'", " ") .split():
					if "." in token and token.isascii():
						ti.malicious_domains.append(token)


