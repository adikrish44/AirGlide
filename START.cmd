@echo off
setlocal
if not exist "%~dp0AirGlide.exe" (
    echo AirGlide.exe is missing from this folder.
    echo Download AirGlide-Windows.zip from the release page:
    echo https://github.com/Adikrish44/AirGlide/releases/latest
    echo Choose Extract All, then run START.cmd in the extracted folder.
    pause
    exit /b 1
)
cd /d "%~dp0"
"%~dp0AirGlide.exe"
if errorlevel 1 pause
