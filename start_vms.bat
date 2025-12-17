@echo off
title VMS Pro - Visitor Management System
color 0A

echo.
echo ============================================================
echo    VMS Pro - Visitor Management System
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from https://python.org
    pause
    exit /b 1
)

echo Checking Python version...
python --version

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies if requirements.txt exists
if exist "requirements.txt" (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Create uploads directory if it doesn't exist
if not exist "uploads" (
    echo Creating uploads directory...
    mkdir uploads
)

echo.
echo ============================================================
echo    Starting VMS Pro Server...
echo ============================================================
echo.
echo Default Login Credentials:
echo   Admin: admin / admin123
echo   Security: security / security123
echo   Employee: employee / employee123
echo.
echo Access URL: http://localhost:5002
echo Press Ctrl+C to stop the server
echo.

REM Start the application
python run.py

pause

