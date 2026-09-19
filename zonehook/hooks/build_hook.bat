@echo off
rem Build one hook DLL.   build_hook.bat <name>   e.g.  build_hook.bat void_bag
rem
rem Builds hooks\<name>\<name>.cpp into hooks\build\<name>.dll, which the loader picks up from the
rem server's hooks\ folder.
rem
rem FULL CRT. A plugin is loaded by zonehook from the SERVICE thread, long after loader init, so it is an
rem ordinary runtime LoadLibrary: normal stack, no loader lock, and the CRT, the STL and C++ exceptions
rem all work.
rem
rem /MT (static CRT) by default, which is deliberate. The static CRT is what killed the LOADER back when
rem everything was one statically-imported DLL - but that was about WHERE it was mapped, not about /MT:
rem a static import is initialised during loader init, on a barely-committed stack, and CRT start-up
rem wants more room than is there. A plugin is loaded much later and has a full stack, so /MT is fine
rem here and leaves the DLL with no redistributable to ship. Pass "dynamic" for /MD if you would rather
rem link the CRT dynamically - then msvcp140.dll and vcruntime140.dll must sit beside the exe.
setlocal
cd /d "%~dp0"

if "%~1"=="" (
  echo usage: build_hook.bat ^<name^>
  echo   plugins:
  for /d %%d in (*) do if not "%%d"=="build" echo     %%d
  exit /b 1
)
if not exist "%~1\%~1.cpp" (
  echo No such plugin: %~1\%~1.cpp
  exit /b 1
)

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat
if not exist "%VCVARS%" (
  echo Cannot find vcvars32.bat at "%VCVARS%" - edit VCVARS in this file.
  echo It must be the 32-BIT environment: Zone.exe is PE32.
  exit /b 1
)
call "%VCVARS%" >nul 2>&1

if not exist build mkdir build
set FLAGS=/nologo /W4 /EHsc /std:c++17 /O2 /MT /I ..\include /Fobuild\ /Fdbuild\%~1.pdb
if /i "%~2"=="dynamic" set FLAGS=/nologo /W4 /EHsc /std:c++17 /O2 /MD /I ..\include /Fobuild\ /Fdbuild\%~1.pdb
if /i "%~2"=="debug" set FLAGS=/nologo /W4 /EHsc /std:c++17 /Od /Zi /MTd /I ..\include /Fobuild\ /Fdbuild\%~1.pdb

cl %FLAGS% /LD "%~1\%~1.cpp" /link /OUT:build\%~1.dll /DEBUG /SUBSYSTEM:WINDOWS ^
   kernel32.lib user32.lib
if errorlevel 1 exit /b 1

echo.
echo   build\%~1.dll
echo.
echo Deploy: copy it into the server's hooks\ folder, next to the patched Zone.exe.
