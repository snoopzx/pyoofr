@echo off
setlocal

REM
set SCRIPT_DIR=%~dp0
set SCRIPT_FILE=%SCRIPT_DIR%spoofer.py

REM
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found.
    echo Please install Python and add it to PATH.
    pause
    exit /b
)

REM
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [INFO] Python detected - version %PY_VER%

:MENU
echo.
echo =============================
echo Press 1 to run spoofer.py as Admin
echo Press 2 to Exit
echo =============================
set /p choice=Your choice: 

if "%choice%"=="1" goto RUNASADMIN
if "%choice%"=="2" exit /b
echo Invalid choice. Try again.
goto MENU

:RUNASADMIN
echo ---------------------------
echo [RUNNING AS ADMIN] spoofer.py ...
echo ---------------------------
powershell -Command "Start-Process cmd -ArgumentList '/k cd /d %SCRIPT_DIR% && python spoofer.py' -Verb RunAs"
exit /b
