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
rem ZH_NO_ODS: Wine implements OutputDebugString by RAISING AN EXCEPTION, and setting one up at
rem DllMain time overflowed the main thread stack and killed the zone before it started
rem (measured 2026-09-19). Build without it only when running under a real Windows debugger.
set FLAGS=/nologo /W4 /EHsc /GS- /std:c++17 /DZH_NO_ODS /DWIN32_LEAN_AND_MEAN /Zc:threadSafeInit- /GR- /Fobuild\ /Fdbuild\
if /i "%~1"=="debug" (set FLAGS=%FLAGS% /Od /Zi /MTd) else (set FLAGS=%FLAGS% /O2 /MT)

rem NO CRT: see src/nocrt.h. A DLL that pulls in the static CRT and is a static import of Zone.exe
rem overflows the main thread stack during CRT start-up under Wine, before DllMain runs.
cl %FLAGS% /LD src\dllmain.cpp src\hook.cpp src\packet_hook.cpp src\nocrt.cpp ^
   /link /OUT:build\zonehook.dll /DEBUG /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:DllMain ^
   kernel32.lib user32.lib
if errorlevel 1 exit /b 1

echo.
echo   build\zonehook.dll
echo.
echo Deploy: put zonehook.dll NEXT TO the patched Zone.exe (same folder - it is an ordinary
echo import, so the loader looks there first). Patch the exe with:
echo   python apply.py recipes/dll-loader.json --exe Zone.exe --out Zone.hooked.exe
