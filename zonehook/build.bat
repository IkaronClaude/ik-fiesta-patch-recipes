@echo off
rem Build fiestahook.dll - the LOADER. 32-bit, to match Zone.exe (PE32) - and Character.exe, the same loader.
rem   build.bat            release
rem   build.bat debug      with symbols and no optimisation
rem
rem The loader is deliberately CRT-FREE: it is a static import of the exe, so it is mapped during loader
rem init on a stack with very little committed, and it has no redistributable dependency. Plugins in
rem hooks/ are loaded later, from the service thread, and are under no such restriction - build those
rem with whatever CRT you like (see hooks/build_hook.bat).
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
set FLAGS=/nologo /W4 /EHsc /GS- /std:c++17 /DZH_NO_ODS /DWIN32_LEAN_AND_MEAN /Zc:threadSafeInit- /GR- /I include /Fobuild\ /Fdbuild\
if /i "%~1"=="debug" (set FLAGS=%FLAGS% /Od /Zi /MTd) else (set FLAGS=%FLAGS% /O2 /MT)

cl %FLAGS% /LD src\dllmain.cpp src\plugins.cpp src\service_hook.cpp src\nocrt.cpp ^
   /link /OUT:build\fiestahook.dll /DEBUG /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:DllMain ^
   kernel32.lib user32.lib advapi32.lib
if errorlevel 1 exit /b 1

echo.
echo   build\fiestahook.dll
echo.
echo Deploy: fiestahook.dll NEXT TO the patched exe (Zone.exe or Character.exe), plugins in a hooks\ subfolder. Patch with:
echo   python apply.py recipes/dll-loader.json --exe Zone.exe --out Zone.hooked.exe
