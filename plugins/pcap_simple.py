name = "pcap_simple"

from pathlib import Path
from typing import Iterable, Dict, Any


def supports() -> Iterable[str]:
	return [".pcap", ".pcapng"]


def parse(path: Path) -> Iterable[Dict[str, Any]]:
	try:
		from scapy.all import rdpcap
	except Exception:
		return []
	try:
		pkts = rdpcap(str(path))
		for p in pkts:
			rec: Dict[str, Any] = {"len": int(getattr(p, "len", 0))}
			# Timestamp
			try:
				rec["ts"] = str(p.time)
			except Exception:
				pass
			# IP fields
			try:
				if hasattr(p, "payload") and hasattr(p.payload, "src") and hasattr(p.payload, "dst"):
					rec["src_ip"] = str(p.payload.src)
					rec["dst_ip"] = str(p.payload.dst)
			except Exception:
				pass
			yield rec
	except Exception:
		return []


