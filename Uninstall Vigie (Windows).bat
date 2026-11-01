@echo off
rem Double-click to remove Vigie for this Windows user.
rem It runs installer\uninstall.ps1, allowing that script for this run only.
rem The window stays open at the end, even when Windows refuses to run the script.
setlocal
set "VIGIE_INSTALL_NO_PAUSE=1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\uninstall.ps1"
if errorlevel 1 (
  echo.
  echo   If no message above says what went wrong, this computer may block
  echo   PowerShell scripts.
)
echo.
pause
