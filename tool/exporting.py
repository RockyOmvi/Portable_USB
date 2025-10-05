from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any, List

import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm


def _extract_events(report: Dict[str, Any]) -> List[Dict[str, Any]]:

	findings = report.get("findings") or {}
	events = findings.get("events") or []
	if not isinstance(events, list):
		return []
	return events


def export_to_json(report: Dict[str, Any], out_path: Path) -> Path:

	out_path = Path(out_path)
	out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
	return out_path


def export_to_csv(report: Dict[str, Any], out_path: Path) -> Path:

	events = _extract_events(report)
	df = pd.json_normalize(events)
	out_path = Path(out_path)
	df.to_csv(out_path, index=False, encoding="utf-8")
	return out_path


def export_to_txt(report: Dict[str, Any], out_path: Path) -> Path:

	out = []
	meta = report.get("meta", {})
	score = report.get("score", 0)
	summary = ((report.get("findings") or {}).get("summary") or {})
	out.append(f"Report ID: {meta.get('id','')}")
	out.append(f"Created: {meta.get('created_utc','')}")
	out.append(f"Severity: {meta.get('severity','')}")
	out.append(f"Score: {score}")
	out.append("")
	out.append("Severity breakdown:")
	for k, v in (summary.get("severity_breakdown") or {}).items():
		out.append(f"  - {k}: {v}")
	out.append("")
	out.append("Events:")
	for i, e in enumerate(_extract_events(report), start=1):
		out.append(f"[{i}] {json.dumps(e, ensure_ascii=False)}")
	out_path = Path(out_path)
	out_path.write_text("\n".join(out), encoding="utf-8")
	return out_path


def export_to_pdf(report: Dict[str, Any], out_path: Path) -> Path:

	c = canvas.Canvas(str(out_path), pagesize=A4)
	width, height = A4
	x_margin = 20 * mm
	y = height - 20 * mm

	def writeln(text: str) -> None:
		nonlocal y
		wrapped = []
		while len(text) > 0:
			if len(text) <= 110:
				wrapped.append(text)
				break
			wrapped.append(text[:110])
			text = text[110:]
		for line in wrapped:
			c.drawString(x_margin, y, line)
			y -= 6 * mm
			if y < 20 * mm:
				c.showPage()
				y = height - 20 * mm

	meta = report.get("meta", {})
	score = report.get("score", 0)
	summary = ((report.get("findings") or {}).get("summary") or {})

	c.setFont("Helvetica-Bold", 14)
	c.drawString(x_margin, y, "Portable USB Log Analysis Report")
	y -= 10 * mm

	c.setFont("Helvetica", 10)
	writeln(f"Report ID: {meta.get('id','')}")
	writeln(f"Created: {meta.get('created_utc','')}")
	writeln(f"Severity: {meta.get('severity','')}")
	writeln(f"Score: {score}")
	y -= 4 * mm

	c.setFont("Helvetica-Bold", 12)
	writeln("Severity breakdown")
	c.setFont("Helvetica", 10)
	for k, v in (summary.get("severity_breakdown") or {}).items():
		writeln(f"- {k}: {v}")
	y -= 4 * mm

	c.setFont("Helvetica-Bold", 12)
	writeln("Events")
	c.setFont("Helvetica", 10)
	for i, e in enumerate(_extract_events(report), start=1):
		writeln(f"[{i}] {json.dumps(e, ensure_ascii=False)}")

	c.save()
	return Path(out_path)


