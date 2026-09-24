@echo off
REM SIH26125 - Blockchain Identity & Access Control Launcher
echo ============================================
echo   SIH26125 - Blockchain Identity System
echo ============================================
echo.

cd /d "%~dp0"

REM Activate virtual environment
call venv\Scripts\activate.bat

echo Starting the server...
echo Open your browser at: http://127.0.0.1:8080
echo Press CTRL+C to stop
echo.

python app.py

pause
