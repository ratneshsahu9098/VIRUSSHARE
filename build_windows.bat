@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo === virusShare build (Windows) ===

where python >nul 2>nul
if errorlevel 1 (
    echo [error] Python was not found on PATH.
    exit /b 1
)

echo [1/4] Installing dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [error] pip install failed.
    exit /b 1
)

echo [2/4] Running test suite...
python -m pytest -q
if errorlevel 1 (
    echo [error] tests failed - refusing to package a broken build.
    exit /b 1
)

echo [3/4] Building executable (PyInstaller)...
python -m PyInstaller --clean --noconfirm virusShare.spec
if errorlevel 1 (
    echo [error] PyInstaller build failed.
    exit /b 1
)

echo [4/4] Done.
echo.
echo     dist\virusShare.exe
echo.
echo Notes:
echo   - first launch creates %%APPDATA%%\virusShare (settings, identity,
echo     trust store, history.db and logs)
echo   - allow Python/virusShare on Private networks in Windows Firewall
echo     for UDP %discovery% / TCP transfer traffic
exit /b 0
