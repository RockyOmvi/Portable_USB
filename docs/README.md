# Portable USB Log Analysis Tool – Ultimate (v3.0)

Run directly from the USB. No host installation needed. Reports are encrypted-at-rest.

Contents
- Overview
- Prerequisites (USB-only mode)
- Plug-and-Play Bootstrap
- Quick Start (Windows/macOS/Linux)
- All Commands (with examples)
- Streaming & Dashboard
- Collectors (Syslog/FTP/Host)
- Reports, Encryption & Signatures
- Exporting (JSON/CSV/TXT/PDF)
- Rules (Sigma/basic) & Threat Intel (STIX/TI files)
- Audit Logging & Secure Deletion
- Self Tests
- Cleanup & Maintenance
- Troubleshooting
 - Central Bundling & Auth
 - Enrichment (GeoIP/ASN)
 - Key Rotation & Manifests

Overview
- Purpose: Analyze logs from removable media or live sources, detect threats, and produce encrypted reports.
- Key features:
  - Plugin-based parsing (CSV, JSONL, SYSLOG, TXT). Add your own under `plugins/`.
  - Advanced analysis (heuristics + ML ensemble + rules + TI).
  - Real-time streaming and TUI dashboard.
  - Encrypted reports (AES-256-GCM) with detached Ed25519 signatures.
  - USB-first, no installation required; optional best-effort autorun launchers.

Prerequisites (USB-only mode)
- Host needs basic shell access to run a script.
- Python is NOT required if you use the USB-local virtual environment (recommended).
- Optional external tools for secure deletion: Windows `sdelete.exe`, Linux `shred`, macOS `srm`.

Plug-and-Play Bootstrap
1) Open a terminal at the USB root
2) Create a local venv and install dependencies into it:
   - Windows/macOS/Linux:
     - `python ./bin/putool.py bootstrap-env`
3) Launch via the OS launcher:
   - Windows: double-click `Run-PUTool.bat`
   - Linux: double-click `Run-PUTool.sh` (mark as trusted) or run `./Run-PUTool.sh`
   - macOS: double-click `Run-PUTool.command` (allow in Gatekeeper if prompted)

Quick Start
- Windows PowerShell:
  - `python .\bin\putool.py analyze-logs --path .\smoke`
  - `python .\bin\putool.py list-reports`
  - `python .\bin\putool.py view-report <REPORT.enc>`
  - `python .\bin\putool.py export-report <REPORT.enc> --format pdf`
  - `python .\bin\putool.py stream --path .\test_stream`
- macOS/Linux:
  - `python3 ./bin/putool.py analyze-logs --path ./smoke`
  - `python3 ./bin/putool.py list-reports`
  - `python3 ./bin/putool.py view-report <REPORT.enc>`
  - `python3 ./bin/putool.py export-report <REPORT.enc> --format pdf`
  - `python3 ./bin/putool.py stream --path ./test_stream`

Folder structure
- bin: entry script
- reports: encrypted reports and keys
- audit: tamper-evident audit logs
- plugins: parsers, rules, TI files
- docs: this manual

All Commands
- analyze-logs
  - Scan a directory and produce an encrypted report.
  - Example: `... analyze-logs --path ./smoke`
- list-reports
  - List encrypted reports in `reports/`.
- view-report NAME
  - Decrypt and display a report.
  - Example: `... view-report report-2025....json.enc`
- export-report NAME --format json|csv|txt|pdf [--out PATH]
  - Export a decrypted report to a chosen format.
  - Example: `... export-report report-... --format pdf`
- delete-report NAME
  - Securely delete an encrypted report.
- stream --path DIR
  - Watch a directory for new/modified files; parse with plugins.
- dashboard [--path DIR]
  - TUI with live stats and top IPs. Defaults to `test_stream/`.
- syslog-listen [--bind 0.0.0.0] [--port 514] [--out ./smoke]
  - UDP syslog listener that appends to a JSONL file under `--out`.
- fetch-ftp --host HOST --username USER --password PASS --remote /path/file [--out ./smoke]
  - Fetch a remote file into USB for analysis.
- analyze-host [--since RANGE]
  - With explicit consent, snapshot limited host logs to a temp folder, then analyze.
- setup-autorun
  - Create best-effort OS launcher files on the USB.
- bootstrap-env
  - Create and populate a USB-local `.venv` for portable use.
- self-test
  - Run a short pipeline test on `smoke/` and export all formats.
- self-test-all
  - Exercise major paths (analyze, export, delete copy, scan_once, host snapshot, autorun setup) and print a summary.
- clean-project [--include-tests] [--include-reports]
  - Remove caches and optional test data/reports.
- bundle-reports [--out reports_bundle.tgz]
  - Create a tar.gz containing all encrypted reports and signatures for central transfer.
- set-password
  - Set an optional password to gate sensitive commands (view/export/delete, syslog-listen, fetch-ftp, dashboard, clean-project, bundle-reports).
- rotate-keys
  - Rotate report encryption keys. Old keys are retained in `.keys.json` for decrypting older reports.
- gen-manifest / verify-manifest
  - Generate and verify a SHA-256 manifest over encrypted reports for integrity checking.

Streaming & Dashboard
- Start streaming: `... stream --path ./test_stream`
- In another shell, drop files into `test_stream/` to see counters increase.
- TUI dashboard with live stats and top IPs: `... dashboard --path ./test_stream`

Collectors (Syslog/FTP/Host)
- Syslog: `... syslog-listen --bind 0.0.0.0 --port 514 --out ./smoke`
- FTP: `... fetch-ftp --host ftp.example.com --username user --password pass --remote /logs/a.log --out ./smoke`
- Host snapshot (consent): `... analyze-host --since 1d`

Reports, Encryption & Signatures
- Encryption: AES-256-GCM with HMAC integrity; keys stored in `reports/.keys.json`.
- Detected findings and meta are encrypted into `report-*.json.enc`.
- Detached signature: if supported, `.sig` is written alongside `.enc` using Ed25519.

Exporting
- Export decrypted content: JSON, CSV (events), TXT (human-readable), PDF (summary + events sample).
- Example: `... export-report <REPORT.enc> --format csv`

Rules & Threat Intel
- Rules (Sigma/basic): place YAML at `plugins/rules.yaml`.
  - Basic example:
    -
      id: failed-ssh
      field: msg
      operator: contains
      value: "Failed password"
      severity: High
- Sigma-style: put Sigma YAMLs or merge into `rules.yaml`. Current mapping supports simple selection keys.
- Threat Intel:
  - `plugins/ti_ips.txt`, `plugins/ti_domains.txt`, `plugins/ti_hashes.txt` (one value per line)
  - STIX JSON: drop `*.stix.json` in `plugins/` (basic indicator parsing supported)

Enrichment (GeoIP/ASN)
- If you have MaxMind MMDB files, place them in `plugins/`:
  - `GeoLite2-City.mmdb` and/or `GeoLite2-ASN.mmdb`
- The analyzer will enrich events (country/city/lat/lon, ASN/org) when IPs are present.

Audit Logging & Secure Deletion
- Every command writes to `audit/audit.jsonl` with chained hashes and optional signatures.
- Secure deletion:
  - Windows: prefers `bin/sdelete.exe` (or PATH)
  - Linux: `shred` if available
  - macOS: `srm` if available
  - Fallback: overwrite + unlink

Self Tests
- Quick: `... self-test`
- Full: `... self-test-all`

Cleanup & Maintenance
- Remove caches only: `... clean-project`
- Remove caches + test data: `... clean-project --include-tests`
- Remove caches + all reports: `... clean-project --include-reports`

Troubleshooting
- Autorun didn’t trigger: use the created launcher (`Run-PUTool.*`). Modern OSes restrict autorun.
- Dependencies missing: run `... bootstrap-env` to create the USB-local venv.
- macOS blocked app: right-click `Run-PUTool.command` → Open (approve in Gatekeeper).
- Permissions: collectors like host logs may require elevated privileges.
- Environment readiness: run `... env-check` to verify venv and optional tools. If venv isn’t active, re-run `bootstrap-env`.

Portable packaging notes (optional)
- You can bundle a portable Python per-OS and wheels in `vendor/` to avoid internet access on first run. Then `bootstrap-env` installs with `--no-index --find-links vendor` automatically.
- Consider adding `bin/sdelete.exe` (Windows) subject to licensing.
