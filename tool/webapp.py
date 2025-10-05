from __future__ import annotations
from pathlib import Path
from flask import Flask, jsonify, send_from_directory, render_template_string
import json
import base64

from .reporting_read import ReportingManager


def create_app(usb_root: Path) -> Flask:
	app = Flask(__name__)
	reports_dir = Path(usb_root) / "reports"
	r = ReportingManager(usb_root)

	@app.get("/api/reports")
	def list_reports():
		items = [p.name for p in sorted(reports_dir.glob("report-*.json.enc"))]
		return jsonify(items)

	@app.get("/api/report/<name>")
	def get_report(name: str):
		# return encrypted bytes as attachment
		return send_from_directory(reports_dir, name, as_attachment=True)

	@app.get("/")
	def index():
		items = [p.name for p in sorted(reports_dir.glob("report-*.json.enc"))]
		return render_template_string(_INDEX_HTML, items=items)

	@app.get("/api/report-summary/<name>")
	def report_summary(name: str):
		data = r.decrypt_report(reports_dir / name)
		meta = data.get("meta", {})
		score = data.get("score", 0)
		sev = meta.get("severity", "")
		findings = data.get("findings") or {}
		summary = findings.get("summary") if isinstance(findings, dict) else {}
		if not isinstance(summary, dict):
			summary = {}
		bd = summary.get("severity_breakdown", {}) if isinstance(summary, dict) else {}
		if not isinstance(bd, dict):
			bd = {}
		return jsonify({"name": name, "severity": sev, "score": score, "breakdown": bd})

	@app.get("/api/report-events/<name>")
	def report_events(name: str):
		data = r.decrypt_report(reports_dir / name)
		findings = data.get("findings") or {}
		events = findings.get("events") if isinstance(findings, dict) else []
		if not isinstance(events, list):
			events = []
		return jsonify({"events": events})

	return app


_INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>USB Log Analysis Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 20px; }
    .grid { display: grid; grid-template-columns: 1fr 2fr; gap: 16px; }
    .card { border: 1px solid #ddd; border-radius: 6px; padding: 12px; }
    .list { max-height: 70vh; overflow: auto; }
    .sev { font-weight: bold; }
    .low { color: #2d6a4f; }
    .med { color: #b68900; }
    .high { color: #b02a37; }
    .crit { color: #7a0611; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #eee; padding: 6px 8px; text-align: left; }
    #chart { height: 220px; }
    .muted { color: #666; }
    button { cursor: pointer; }
  </style>
</head>
<body>
  <h1>USB Log Analysis Dashboard</h1>
  <div class="grid">
    <div class="card list">
      <h3>Reports</h3>
      <ul id="reports">
        {% for name in items %}
          <li><a href="#" onclick="selectReport('{{name}}'); return false;">{{name}}</a> &nbsp; <a href="/api/report/{{name}}">[download]</a></li>
        {% endfor %}
      </ul>
    </div>
    <div class="card">
      <h3>Summary</h3>
      <div id="summary" class="muted">Select a report…</div>
      <canvas id="chart"></canvas>
    </div>
  </div>
  <div class="card" style="margin-top:16px;">
    <h3>Events (first 100)</h3>
    <table>
      <thead><tr><th>#</th><th>Event</th></tr></thead>
      <tbody id="events"></tbody>
    </table>
  </div>

  <script>
    async function selectReport(name) {
      const s = await fetch(`/api/report-summary/${encodeURIComponent(name)}`).then(r => r.json());
      const e = await fetch(`/api/report-events/${encodeURIComponent(name)}`).then(r => r.json());
      const sevClass = (sev) => ({"Low":"low","Medium":"med","High":"high","Critical":"crit"}[sev]||"");
      const sum = document.getElementById('summary');
      sum.innerHTML = `<div>Severity: <span class="sev ${sevClass(s.severity)}">${s.severity}</span> &nbsp; Score: <b>${s.score}</b></div>`;
      const bd = s.breakdown || {}; const labels = Object.keys(bd); const vals = labels.map(k => bd[k]);
      drawChart(labels, vals);
      const tbody = document.getElementById('events');
      tbody.innerHTML = '';
      (e.events || []).slice(0, 100).forEach((ev, i) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${i+1}</td><td><pre style="margin:0;white-space:pre-wrap;">${escapeHtml(JSON.stringify(ev))}</pre></td>`;
        tbody.appendChild(tr);
      });
    }
    function escapeHtml(s){return s.replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]))}
    function drawChart(labels, vals){
      const c = document.getElementById('chart');
      const ctx = c.getContext('2d');
      c.width = c.clientWidth; c.height = 220;
      ctx.clearRect(0,0,c.width,c.height);
      const max = Math.max(1, ...vals);
      const barW = Math.max(20, Math.floor((c.width - 40) / Math.max(1, labels.length)));
      labels.forEach((lab, i) => {
        const h = Math.round((vals[i] / max) * 180);
        const x = 20 + i * barW; const y = 200 - h;
        ctx.fillStyle = '#4c78a8';
        ctx.fillRect(x, y, barW - 8, h);
        ctx.fillStyle = '#333';
        ctx.fillText(lab, x, 215);
      });
    }
  </script>
</body>
</html>
"""


