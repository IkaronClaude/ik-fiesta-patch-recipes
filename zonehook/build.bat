@echo off
rem Build zonehook.dll - 32-bit, to match Zone.exe (PE32).
rem   build.bat            release
rem   build.bat debug      with symbols and no optimisation
setlocal
cd /d "%~dp0"

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat
if not exist "%VCVARS%" (
  echo Cannot find vcvars32.bat at:
  echo   %VCVARS%
  echo Edit VCVARS in this file to point at your Visual Studio, and note it must be the 32-BIT
  echo environment - Zone.exe is PE32 and a 64-bit DLL will not load into it.
  exit /b 1
)
call "%VCVARS%" >nul 2>&1

if not exist build mkdir build
set FLAGS=/nologo /W4 /EHsc /GS- /std:c++17 /DWIN32_LEAN_AND_MEAN /Fobuild\ /Fdbuild\
if /i "%~1"=="debug" (set FLAGS=%FLAGS% /Od /Zi /MTd) else (set FLAGS=%FLAGS% /O2 /MT)

cl %FLAGS% /LD src\dllmain.cpp src\hook.cpp src\packet_hook.cpp ^
   /link /OUT:build\zonehook.dll /DEBUG /SUBSYSTEM:WINDOWS kernel32.lib user32.lib
if errorlevel 1 exit /b 1

echo.
echo   build\zonehook.dll
echo.
echo Deploy: put zonehook.dll NEXT TO the patched Zone.exe (same folder - it is an ordinary
echo import, so the loader looks there first). Patch the exe with:
echo   python apply.py recipes/dll-loader.json --exe Zone.exe --out Zone.hooked.exe
