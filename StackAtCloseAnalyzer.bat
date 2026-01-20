@echo off
REM Windows launcher for StackAtClose Analyzer
REM Works on Windows 7, 8, 10, 11

python StackAtCloseAnalyzer.py %*
if errorlevel 1 (
    echo.
    echo ERROR: Python 3 is required but not found!
    echo Please install Python 3.8 or higher from https://python.org
    echo.
    pause
)
