from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Any, List
from datetime import datetime, timedelta
from dateutil import parser as dtparser


@dataclass
class CorrelationHit:
	pattern: str
	indices: List[int]
	severity: str


def parse_ts(e: Dict[str, Any]) -> datetime | None:
	for k in ("ts", "timestamp", "time"):
		v = e.get(k)
		if isinstance(v, str):
			try:
				return dtparser.parse(v)
			except Exception:
				continue
	return None


def correlate(events: List[Dict[str, Any]], window_seconds: int = 600) -> List[CorrelationHit]:
	"""Detect simple sequences within a time window.
	Patterns:
	1) Multiple failed logins followed by a success from same user/ip
	2) Privilege escalation after login success
	"""
	hits: List[CorrelationHit] = []
	win = timedelta(seconds=window_seconds)
	# Pre-extract minimal fields
	summaries = []
	for idx, e in enumerate(events):
		dt = parse_ts(e) or datetime.min
		msg = str(e.get("msg", "")).lower()
		user = str(e.get("user", ""))
		src = str(e.get("src_ip", e.get("ip", e.get("remote_ip", ""))))
		summaries.append((idx, dt, msg, user, src))
	# 1) Failed -> success
	fails: Dict[str, Deque[int]] = {}
	for idx, dt, msg, user, src in summaries:
		key = f"{user}|{src}"
		if "failed" in msg or "invalid" in msg:
			fails.setdefault(key, deque()).append(idx)
			# drop old
			while fails[key] and parse_ts(events[fails[key][0]]) and (dt - (parse_ts(events[fails[key][0]]) or dt)) > win:
				fails[key].popleft()
		elif "success" in msg or "accepted" in msg:
			# hit if we have >=3 recent fails
			q = fails.get(key)
			if q and len(q) >= 3:
				seq = list(q)[-3:] + [idx]
				hits.append(CorrelationHit(pattern="bruteforce_then_success", indices=seq, severity="High"))
	# 2) Privilege escalation after success
	last_success: Dict[str, int] = {}
	for idx, dt, msg, user, src in summaries:
		key = f"{user}|{src}"
		if "success" in msg or "accepted" in msg:
			last_success[key] = idx
		elif any(k in msg for k in ["sudo", "privilege", "admin", "su "]):
			j = last_success.get(key)
			if j is not None:
				dt_prev = parse_ts(events[j]) or dt
				if (dt - dt_prev) <= win:
					hits.append(CorrelationHit(pattern="priv_escalation_after_login", indices=[j, idx], severity="High"))
	return hits


