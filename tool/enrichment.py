from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Optional


class Enricher:
	def __init__(self, plugins_dir: Path) -> None:
		self.plugins_dir = Path(plugins_dir)
		self._geo_reader = self._open_mmdb("GeoLite2-City.mmdb")
		self._asn_reader = self._open_mmdb("GeoLite2-ASN.mmdb")

	def _open_mmdb(self, name: str):
		try:
			import geoip2.database  # type: ignore
		except Exception:
			return None
		path = self.plugins_dir / name
		if not path.exists():
			return None
		try:
			return geoip2.database.Reader(str(path))
		except Exception:
			return None

	def close(self) -> None:
		try:
			if self._geo_reader:
				self._geo_reader.close()
		except Exception:
			pass
		try:
			if self._asn_reader:
				self._asn_reader.close()
		except Exception:
			pass

	def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
		ip = None
		for k in ("src_ip", "ip", "remote_ip", "dst_ip"):
			v = event.get(k)
			if isinstance(v, str) and v:
				ip = v
				break
		if ip and self._geo_reader:
			try:
				resp = self._geo_reader.city(ip)
				geo = {
					"country": getattr(resp.country, "iso_code", None),
					"city": getattr(resp.city, "name", None),
					"lat": getattr(getattr(resp.location, "latitude", None), "real", None) if hasattr(resp.location, "latitude") else getattr(resp.location, "latitude", None),
					"lon": getattr(getattr(resp.location, "longitude", None), "real", None) if hasattr(resp.location, "longitude") else getattr(resp.location, "longitude", None),
				}
				event.setdefault("geo", geo)
			except Exception:
				pass
		if ip and self._asn_reader:
			try:
				resp = self._asn_reader.asn(ip)
				asn = {"asn": getattr(resp, "autonomous_system_number", None), "org": getattr(resp, "autonomous_system_organization", None)}
				event.setdefault("asn", asn)
			except Exception:
				pass
		return event


