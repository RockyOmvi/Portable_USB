@echo off
setlocal enableextensions
set ROOT=%~dp0
set PY=%ROOT%.venv\Scripts\python.exe
if not exist "%PY%" set PY=python

echo Using Python: %PY%
pushd "%ROOT%"

echo [0/6] Ensure dependencies installed into USB venv
"%PY%" bin\putool.py bootstrap-env

echo [1/6] Environment check
"%PY%" bin\putool.py env-check

echo [2/6] Analyze sample logs (./smoke)
"%PY%" bin\putool.py analyze-logs --path .\smoke

echo [3/6] List reports ^(may require password if set^)
if not exist audit\.auth.json (
  "%PY%" bin\putool.py list-reports
) else (
  echo Skipping list-reports ^(password protected^). Run manually if needed.
)

echo [4/6] Full self-test (may take a moment)
"%PY%" bin\putool.py self-test-all

echo [5/6] Generate manifest over encrypted reports
"%PY%" bin\putool.py gen-manifest

echo [6/6] Bundle encrypted reports ^(skipped if password set^)
if not exist audit\.auth.json (
  "%PY%" bin\putool.py bundle-reports --out .\reports_bundle.tgz
) else (
  echo Skipping bundle-reports ^(password protected^). Run manually if needed.
)

echo.
set /p RUN_STREAM="Run streaming demo now (watches .\\test_stream)? (Y/N): "
if /I "%RUN_STREAM%"=="Y" (
  echo Starting streaming in a new window. Close that window to stop.
  start "Streaming" cmd /k "%PY%" bin\putool.py stream --path .\test_stream
)

echo.
set /p RUN_DASH_TUI="Run TUI dashboard now (reads .\\test_stream)? (Y/N): "
if /I "%RUN_DASH_TUI%"=="Y" (
  echo Starting TUI dashboard in a new window. Close that window to stop.
  start "Dashboard TUI" cmd /k "%PY%" bin\putool.py dashboard --path .\test_stream
)

echo.
set /p RUN_DASH_WEB="Run Web dashboard now (http://127.0.0.1:8080)? (Y/N): "
if /I "%RUN_DASH_WEB%"=="Y" (
  echo Starting Web dashboard in a new window. Press Ctrl+C in that window to stop.
  start "Dashboard Web" cmd /k "%PY%" bin\putool.py web-dashboard --host 0.0.0.0 --port 0
)

echo Done.
popd
endlocal

