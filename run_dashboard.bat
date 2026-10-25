@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or newer was not found. Install Python and enable Add Python to PATH.
  pause
  exit /b 1
)
echo Checking required Python packages...
python -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo.
  echo Package installation failed. Check your internet connection and Python installation.
  pause
  exit /b 1
)
echo Starting AIRGUARD...
python dashboard.py
if errorlevel 1 (
  echo.
  echo Dashboard exited with an error. Check the message above.
  pause
)
