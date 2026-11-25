@echo off
setlocal
cd /d "%~dp0"
py -3.12 run_demo.py
if errorlevel 1 py -3.11 run_demo.py
if errorlevel 1 py -3.13 run_demo.py
if errorlevel 1 (
  echo.
  echo VaultShield did not start. Check the error above.
  pause
)
endlocal
