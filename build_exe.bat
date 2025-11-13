@echo off
REM Cerberus Agents - EXE Build Script (Windows)

echo =========================================
echo Cerberus Agents - EXE Builder
echo =========================================
echo.

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo Building executables with PyInstaller...
echo.

if not exist dist mkdir dist

set AGENTS=asset_discovery_agent automated_recon_reporter credential_checker tiny_canary_agent pentest_task_runner incident_triage_helper central_collector

for %%a in (%AGENTS%) do (
    echo Building %%a...
    pyinstaller --onefile ^
                --name=%%a ^
                --clean ^
                --distpath=dist ^
                --workpath=build\%%a ^
                --specpath=build ^
                cerberus_agents\%%a.py
    echo ✓ %%a built successfully
    echo.
)

echo =========================================
echo Build Complete!
echo =========================================
echo.
echo Executables are in the 'dist' directory:
dir dist
echo.
echo To code-sign executables (Windows):
echo   signtool sign /f certificate.pfx /p password dist\agent_name.exe
echo.
echo Press any key to exit...
pause >nul
