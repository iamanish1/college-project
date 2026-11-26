@echo off
REM One-command start for Mini Guardrail on Windows.
REM Usage:  start.bat                 (setup + tests + server + browser)
REM         start.bat -Port 8080 -SkipTests -NoBrowser
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
