from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Dict, Tuple
from datetime import datetime


SCHEMA = """
CREATE TABLE IF NOT EXISTS entity_counts (
  feature TEXT NOT NULL,
  value TEXT NOT NULL,
  count INTEGER NOT NULL,
  last_updated_utc TEXT NOT NULL,
  PRIMARY KEY(feature, value)
);
"""


class BaselineStore:
	def __init__(self, db_path: Path) -> None:
		self.db_path = Path(db_path)
		self.db_path.parent.mkdir(parents=True, exist_ok=True)
		self._init()

	def _init(self) -> None:
		with sqlite3.connect(self.db_path) as con:
			con.execute(SCHEMA)

	def increment_counts(self, feature_to_value_to_count: Dict[str, Dict[str, int]]) -> None:
		utc = datetime.utcnow().isoformat() + "Z"
		with sqlite3.connect(self.db_path) as con:
			for feature, mapping in feature_to_value_to_count.items():
				for value, inc in mapping.items():
					con.execute(
						"INSERT INTO entity_counts(feature, value, count, last_updated_utc) VALUES(?,?,?,?) "
						"ON CONFLICT(feature, value) DO UPDATE SET count = count + excluded.count, last_updated_utc = excluded.last_updated_utc",
						(feature, value, int(inc), utc),
					)

	def load_stats(self, feature: str) -> Dict[str, int]:
		with sqlite3.connect(self.db_path) as con:
			rows = con.execute("SELECT value, count FROM entity_counts WHERE feature=?", (feature,)).fetchall()
			return {str(v): int(c) for (v, c) in rows}


