from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.decomposition import TruncatedSVD
from pathlib import Path
from .rules import load_rules, rule_match, load_sigma_from_dir
from .intel import load_feeds, is_malicious_ip
import json
from datetime import datetime
from dateutil import parser as dtparser
from .baselines import BaselineStore
from .correlator import correlate
from .enrichment import Enricher


@dataclass
class AnalysisResult:
	severity_breakdown: Dict[str, int]
	score: int
	events: List[Dict[str, Any]]


class AnalysisEngine:
	def __init__(self) -> None:
		self.iforest = IsolationForest(n_estimators=200, contamination=0.08, random_state=42)
		self.ocsvm = OneClassSVM(kernel="rbf", gamma="auto")
		self.lof = LocalOutlierFactor(n_neighbors=20, contamination=0.08, novelty=True)
		self.text_vectorizer = HashingVectorizer(n_features=2**12, alternate_sign=False, norm="l2")
		self.text_svd = TruncatedSVD(n_components=16, random_state=42)
		self.baselines_db: Path | None = None
		self.rules_path: Path | None = None
		self.plugins_dir: Path | None = None

	def configure(self, rules_path: Path | None = None, plugins_dir: Path | None = None) -> None:
		self.rules_path = rules_path
		self.plugins_dir = plugins_dir
		# Baselines DB under reports to keep on USB
		if self.plugins_dir is not None:
			self.baselines_db = Path(self.plugins_dir).parents[0] / "reports" / ".baselines.sqlite"
		self._enricher = Enricher(self.plugins_dir) if self.plugins_dir is not None else None

	def _heuristic_score(self, event: Dict[str, Any]) -> int:
		score = 0
		text = str(event)
		for kw, w in [("error", 10), ("fail", 8), ("unauthorized", 15), ("suspicious", 12)]:
			if kw in text.lower():
				score += w
		return score

	def _severity(self, score: int) -> str:
		if score >= 90:
			return "Critical"
		if score >= 70:
			return "High"
		if score >= 40:
			return "Medium"
		return "Low"

	def analyze(self, events: List[Dict[str, Any]]) -> AnalysisResult:
		if not events:
			return AnalysisResult(severity_breakdown={"Low": 0, "Medium": 0, "High": 0, "Critical": 0}, score=0, events=[])

		features = []
		heuristic_scores = []
		texts: List[str] = []
		for e in events:
			# Enrich with GeoIP/ASN when available
			try:
				if self._enricher is not None:
					self._enricher.enrich_event(e)
			except Exception:
				pass
			text_len = len(str(e))
			hs = self._heuristic_score(e)
			features.append([text_len, hs])
			heuristic_scores.append(hs)
			texts.append(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
		X = np.array(features, dtype=float)
		# Textual features
		try:
			Xt = self.text_vectorizer.transform(texts)
			Xt = self.text_svd.fit_transform(Xt)
		except Exception:
			Xt = np.zeros((len(events), 16))
		# Concatenate
		X_all = np.concatenate([X, Xt], axis=1) if len(events) else X

		# Per-entity frequency baselines (within-batch z-scores)
		entity_fields = ["src_ip", "dst_ip", "proc", "user", "host"]
		entity_counts: Dict[str, Dict[str, int]] = {f: {} for f in entity_fields}
		for e in events:
			for f in entity_fields:
				v = e.get(f)
				if isinstance(v, str):
					entity_counts[f][v] = entity_counts[f].get(v, 0) + 1
		entity_stats: Dict[str, Dict[str, float]] = {f: {} for f in entity_fields}
		for f in entity_fields:
			vals = list(entity_counts[f].values())
			if not vals:
				continue
			mu = float(np.mean(vals))
			sd = float(np.std(vals)) or 1.0
			for v, c in entity_counts[f].items():
				entity_stats[f][v] = (c - mu) / sd

		# Persistent baselines: compare with historical counts if DB configured
		if self.baselines_db is not None:
			store = BaselineStore(self.baselines_db)
			hist_bonus = {f: {} for f in entity_fields}
			for f in entity_fields:
				hist = store.load_stats(f)
				if not hist:
					continue
				mu_h = float(np.mean(list(hist.values())))
				sd_h = float(np.std(list(hist.values()))) or 1.0
				for v, c in entity_counts[f].items():
					z = (c - mu_h) / sd_h
					hist_bonus[f][v] = z
		else:
			hist_bonus = {f: {} for f in entity_fields}

		# Temporal burst detection (per-minute bucket counts z-score)
		def parse_ts(ev: Dict[str, Any]) -> datetime | None:
			for k in ("ts", "timestamp", "time"):
				val = ev.get(k)
				if isinstance(val, str):
					try:
						return dtparser.parse(val)
					except Exception:
						continue
			return None
		bucket_counts: Dict[str, int] = {}
		buckets_for_event: List[str] = []
		for e in events:
			dt = parse_ts(e)
			if dt is None:
				b = "unknown"
			else:
				b = dt.strftime("%Y-%m-%dT%H:%M")
			bucket_counts[b] = bucket_counts.get(b, 0) + 1
			buckets_for_event.append(b)
		vals = list(bucket_counts.values())
		if vals:
			mu_b = float(np.mean(vals))
			sd_b = float(np.std(vals)) or 1.0
			bucket_z: Dict[str, float] = {k: (c - mu_b) / sd_b for k, c in bucket_counts.items()}
		else:
			bucket_z = {}

		try:
			self.iforest.fit(X_all)
			if_scores = -self.iforest.score_samples(X_all)
		except Exception:
			if_scores = np.zeros(len(events))
		try:
			self.ocsvm.fit(X_all)
			oc_scores = -self.ocsvm.score_samples(X_all)
		except Exception:
			oc_scores = np.zeros(len(events))
		try:
			self.lof.fit(X_all)
			lof_scores = -self.lof.score_samples(X_all)
		except Exception:
			lof_scores = np.zeros(len(events))

		sev_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

		# Rule-based and Threat Intel correlation
		# Load combined rules: simple file and Sigma directory under plugins/sigma
		rules = []
		if self.rules_path:
			rules.extend(load_rules(self.rules_path))
		if self.plugins_dir:
			rules.extend(load_sigma_from_dir(Path(self.plugins_dir) / "sigma"))
		ti = load_feeds(self.plugins_dir) if self.plugins_dir else None
		combined_scores: List[int] = []
		for idx, (hs, ifs, ocs, lfs) in enumerate(zip(heuristic_scores, if_scores, oc_scores, lof_scores)):
			bonus = 0
			# Rule hits increase score
			for r in rules:
				try:
					if rule_match(r, events[idx]):
						bonus += 15 if r.severity == "Medium" else 25 if r.severity == "High" else 35
				except Exception:
					pass
			# Threat intel simple IP match
			if ti is not None:
				for key in ("src_ip", "dst_ip", "ip", "remote_ip"):
					v = events[idx].get(key)
					if isinstance(v, str) and is_malicious_ip(ti, v):
						bonus += 30
						break
			# Entity z-score bonus
			for f in entity_fields:
				v = events[idx].get(f)
				if isinstance(v, str):
					z = entity_stats.get(f, {}).get(v, 0.0)
					if z > 2.0:
						bonus += min(20, int(5 * z))
					hb = hist_bonus.get(f, {}).get(v, 0.0)
					if hb > 2.5:
						bonus += min(25, int(6 * hb))
			# Temporal burst bonus
			b = buckets_for_event[idx] if idx < len(buckets_for_event) else None
			if b is not None:
				bz = bucket_z.get(b, 0.0)
				if bz > 2.0:
					bonus += min(20, int(5 * bz))
			# Ensemble aggregation
			an = 0.4 * ifs + 0.35 * ocs + 0.25 * lfs
			combined = int(min(100, hs * 2 + an * 50 + bonus))
			combined_scores.append(combined)
			sev_counts[self._severity(combined)] += 1

		overall = int(np.percentile(combined_scores, 90)) if combined_scores else 0
		# Correlation hits boost overall score slightly
		try:
			corr = correlate(events)
			if corr:
				overall = min(100, int(overall + min(20, 5 * len(corr))))
		except Exception:
			pass
		# Update persistent baselines after analysis
		if self.baselines_db is not None:
			store = BaselineStore(self.baselines_db)
			store.increment_counts(entity_counts)
		# Close enricher if used
		try:
			if self._enricher is not None:
				self._enricher.close()
		except Exception:
			pass
		return AnalysisResult(severity_breakdown=sev_counts, score=overall, events=events)
