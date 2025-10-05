@echo off
set VENV=%~dp0.venv\Scripts\python.exe
if exist "%VENV%" (
  "%VENV%" %~dp0bin\putool.py list-reports
) else (
  python %~dp0bin\putool.py list-reports
)
pause
