@echo off
REM SIH26125 - HTTPS launcher (encrypted connection, removes the browser "Not secure" badge)
echo ============================================
echo   SIH26125 - Blockchain Identity System (HTTPS)
echo ============================================
echo.

cd /d "%~dp0"

REM Activate virtual environment
call venv\Scripts\activate.bat

echo Starting the server over HTTPS (self-signed)...
echo Open your browser at: https://localhost:8080
echo First visit: click "Advanced" then "Proceed to site" once
echo Press CTRL+C to stop
echo.

python app.py --https

pause