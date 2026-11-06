@echo off
setlocal
cd /d "%~dp0"
AirGlide.exe
if errorlevel 1 pause
