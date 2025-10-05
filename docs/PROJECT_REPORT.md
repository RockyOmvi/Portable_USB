# Portable USB Log Analysis Tool – Ultimate (v3.0)

## 1. Overview
A self-contained, USB-only log analysis suite for isolated and central environments. It collects, parses, analyzes, and reports on security-relevant logs fully offline, with encrypted outputs and tamper-evident auditing.

- Cross-platform: Windows, Linux, macOS
- USB-first: runs from the flash drive; no host installation
- Offline: no external cloud dependencies

## 2. Folder Structure
- `bin/`: entry script `putool.py`
- `tool/`: core modules (CLI, analysis, reporting, crypto, streaming, collectors, auth, web/TUI, etc.)
- `plugins/`: parsers (CSV/JSONL/Syslog/TXT/PCAP/NetFlow), rules (Sigma), threat intel (STIX/TI files), optional MMDBs
- `reports/`: AES-256-GCM encrypted reports and signatures
- `audit/`: tamper-evident audit logs and auth config
- `docs/`: README and this report

## 3. USB‑Only Deployment
1) Copy the project to the USB root
2) Bootstrap the local venv and install deps into the USB:
   - Windows/macOS/Linux: `python ./bin/putool.py bootstrap-env`
3) Optional: `python ./bin/putool.py set-password`
4) Verify: `python ./bin/putool.py env-check`

Launchers (best-effort autorun):
- `python ./bin/putool.py setup-autorun` then use `Run-PUTool.*` after reinsertion

## 4. Key Features
- Multi-source collection: USB-imported, Syslog (UDP), FTP fetch, host snapshot (consent)
- Parsing/normalization: plugins for `.csv`, `.jsonl`, `.log/.syslog`, `.txt`, `.pcap/.pcapng`, NetFlow-like `.csv`
- Analysis (defense-in-depth):
  - Heuristics + ML ensemble (IsolationForest, OneClassSVM, LOF)
  - Text vectorization (HashingVectorizer + SVD)
  - Per-entity baselines (z-scores) and temporal burst detection
  - Persistent baselines via SQLite across runs
  - Rule-based engine with Sigma YAML support
  - Threat intel: TI text files + local STIX JSON
  - Correlation windows (e.g., brute-force → success, privilege escalation)
- Real-time processing: directory watch with fallback polling
- Dashboards:
  - TUI: live stats and top IPs
  - Web UI: report list, decrypted summaries, severity chart, events (first 100)
- Reporting & Security:
  - Encrypted reports: AES-256-GCM + HMAC; detached Ed25519 signatures
  - Key rotation with backward-compatible decryption
  - Integrity manifests (SHA-256) and tamper-evident audit chain
  - Secure deletion with OS tools or fallback overwrite+unlink
- USB-only: local venv, no host install; offline friendly

## 5. Commands (high-level)
- Analyze: `analyze-logs --path DIR`, `analyze-host [--since]`
- Reports: `list-reports`, `view-report NAME`, `export-report NAME --format json|csv|txt|pdf`, `delete-report NAME`
- Streaming/Dashboards: `stream --path DIR`, `dashboard [--path DIR]`, `web-dashboard [--host][--port]`
- Collectors: `syslog-listen`, `fetch-ftp --host ... --remote ...`
- Security: `set-password`, `rotate-keys`, `gen-manifest`, `verify-manifest`
- Packaging: `bootstrap-env`, `setup-autorun`, `env-check`, `bundle-reports`, `clean-project`

See `docs/README.md` for full command details and examples.

## 6. Plugins, Rules, and Intelligence
- Add parsers by dropping `.py` files into `plugins/`
- Sigma rules: place YAMLs in `plugins/sigma/` or `plugins/rules.yaml`
- Threat intel: `plugins/ti_ips.txt`, `ti_domains.txt`, `ti_hashes.txt`; STIX: `plugins/*.stix.json`
- Enrichment: put `GeoLite2-City.mmdb` and/or `GeoLite2-ASN.mmdb` in `plugins/`

## 7. Reports and Audit
- Encrypted reports: `reports/report-*.json.enc` (+ `.sig`)
- Keys stored under `reports/.keys.json` with rotation history
- Audit: `audit/audit.jsonl` with chained hashes and optional signatures

## 8. Security Model
- No plaintext reports stored by default
- Optional password gates sensitive operations
- Secure deletion attempts best-available method per OS
- All operations logged in audit chain

## 9. Web & TUI Dashboards
- TUI dashboard: live counters, top IPs (fields + regex extraction)
- Web dashboard: local-only viewer with summaries and events; downloads encrypted files

## 10. Maintenance & Updates
- Drop new plugins/rules/TI in `plugins/`
- Rotate keys: `rotate-keys`
- Bundle encrypted outputs: `bundle-reports`
- Validate environment: `env-check`

## 11. Troubleshooting
- Autorun blocked: use `Run-PUTool.*` manually (OS policy)
- Flask port errors: use `web-dashboard --host 0.0.0.0 --port 0`
- TUI shows no data: keep it running and copy logs into the watched directory
- Missing optional tools (sdelete/shred/srm): fallback is used

## 12. Roadmap (optional)
- Additional correlation patterns; deeper DPI/NetFlow fields
- CI matrix and fuzzing for parsers

---
This report summarizes the implemented architecture, capabilities, and usage for the Portable USB Log Analysis Tool – Ultimate.
