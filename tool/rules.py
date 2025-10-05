from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List
from pathlib import Path
import fnmatch
import yaml


@dataclass
class Rule:
	id: str
	field: str
	operator: str
	value: Any
	severity: str = "Medium"
	# Optional Sigma-like metadata
	logsource: Dict[str, Any] | None = None
	attack: List[str] | None = None


def load_rules(path: Path) -> List[Rule]:
	path = Path(path)
	if not path.exists():
		return []
	data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
	rules: List[Rule] = []
	for item in data:
		# Sigma list-of-docs compatibility: map 'detection' simple contains
		if "detection" in item and "logsource" in item:
			detection = item["detection"] or {}
			logsource = item["logsource"]
			sev = str(item.get("level", "Medium"))
			# naive mapping: for each selection key/value list, create rules
			for sel_name, sel_body in detection.items():
				if not isinstance(sel_body, dict):
					continue
				for k, v in sel_body.items():
					if isinstance(v, list):
						for vi in v:
							rules.append(Rule(id=f"{item.get('id', item.get('title', 'sigma'))}:{sel_name}:{k}", field=str(k), operator="contains", value=vi, severity=sev, logsource=logsource, attack=item.get("tags")))
					else:
						rules.append(Rule(id=f"{item.get('id', item.get('title', 'sigma'))}:{sel_name}:{k}", field=str(k), operator="contains", value=v, severity=sev, logsource=logsource, attack=item.get("tags")))
			continue
		# Simple custom rule format
		rules.append(Rule(
			id=str(item.get("id")),
			field=str(item.get("field")),
			operator=str(item.get("operator")),
			value=item.get("value"),
			severity=str(item.get("severity", "Medium")),
		))
	return rules


def load_sigma_from_dir(root: Path) -> List[Rule]:
	root = Path(root)
	if not root.exists():
		return []
	collected: List[Rule] = []
	for p in list(root.glob("*.yml")) + list(root.glob("*.yaml")):
		try:
			data = yaml.safe_load(p.read_text(encoding="utf-8"))
			if isinstance(data, list):
				for item in data:
					collected.extend(load_rules_from_item(item))
			else:
				collected.extend(load_rules_from_item(data))
		except Exception:
			continue
	return collected


def load_rules_from_item(item: dict) -> List[Rule]:
	res: List[Rule] = []
	if not isinstance(item, dict):
		return res
	# Reuse Sigma mapping branch in load_rules
	if "detection" in item and "logsource" in item:
		detection = item["detection"] or {}
		logsource = item["logsource"]
		sev = str(item.get("level", "Medium"))
		for sel_name, sel_body in detection.items():
			if not isinstance(sel_body, dict):
				continue
			for k, v in sel_body.items():
				if isinstance(v, list):
					for vi in v:
						res.append(Rule(id=f"{item.get('id', item.get('title', 'sigma'))}:{sel_name}:{k}", field=str(k), operator="contains", value=vi, severity=sev, logsource=logsource, attack=item.get("tags")))
				else:
					res.append(Rule(id=f"{item.get('id', item.get('title', 'sigma'))}:{sel_name}:{k}", field=str(k), operator="contains", value=v, severity=sev, logsource=logsource, attack=item.get("tags")))
		return res
	# Fallback to simple format
	try:
		res.append(Rule(
			id=str(item.get("id")),
			field=str(item.get("field")),
			operator=str(item.get("operator")),
			value=item.get("value"),
			severity=str(item.get("severity", "Medium")),
		))
	except Exception:
		pass
	return res


def rule_match(rule: Rule, event: Dict[str, Any]) -> bool:
	val = event
	for part in rule.field.split('.'):
		if isinstance(val, dict) and part in val:
			val = val[part]
		else:
			val = None
			break
	if val is None:
		return False
	text = str(val)
	op = rule.operator.lower()
	if op == "contains":
		return str(rule.value).lower() in text.lower()
	if op == "equals":
		return text == str(rule.value)
	if op == "glob":
		return fnmatch.fnmatch(text, str(rule.value))
	if op == "regex":
		import re
		return re.search(str(rule.value), text) is not None
	return False


