@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem ===================================================================
rem  AEGIS launcher (backup entry point, ASCII only on purpose)
rem
rem  NOTE: this file contains NO non-ASCII characters by design.
rem  cmd.exe parses .bat files using the OEM code page, so a UTF-8
rem  batch file with Chinese text gets mangled and the script breaks.
rem  Keep this file ASCII-only.
rem
rem  Main entry point is Aegis.py / Aegis.pyw -- use those if you can.
rem ===================================================================

set "ENTRY=%~dp0Aegis.pyw"
set "PYW="

rem --- 1) ask the py launcher ---------------------------------------
for /f "delims=" %%i in ('py -3.13 -c "import sys,os;print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" 2^>nul') do set "PYW=%%i"
if exist "%PYW%" goto run

set "PYW="
for /f "delims=" %%i in ('py -3 -c "import sys,os;print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" 2^>nul') do set "PYW=%%i"
if exist "%PYW%" goto run

rem --- 2) well-known install locations (newest wins) ----------------
if exist "%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe"
if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
if exist "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe"
if exist "C:\Python313\pythonw.exe" set "PYW=C:\Python313\pythonw.exe"
if exist "%ProgramFiles%\Python313\pythonw.exe" set "PYW=%ProgramFiles%\Python313\pythonw.exe"
if exist "%ProgramFiles%\Python312\pythonw.exe" set "PYW=%ProgramFiles%\Python312\pythonw.exe"
if exist "%PYW%" goto run

rem --- 3) pythonw on PATH -------------------------------------------
where pythonw >nul 2>nul
if not errorlevel 1 (
    start "" pythonw "%ENTRY%"
    exit /b 0
)

rem --- 4) python on PATH --------------------------------------------
where python >nul 2>nul
if not errorlevel 1 (
    start "" python "%ENTRY%"
    exit /b 0
)

echo.
echo   [AEGIS] Python not found.
echo.
echo   Install Python 3.8 or newer, and tick
echo   "Add python.exe to PATH" during setup:
echo.
echo       https://www.python.org/downloads/
echo.
echo   Or just double-click Aegis.pyw in this folder.
echo.
pause
exit /b 1

:run
start "" "%PYW%" "%ENTRY%"
exit /b 0
