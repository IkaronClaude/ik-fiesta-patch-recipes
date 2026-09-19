@echo off
rem Build one hook plugin.   common\build_plugin.bat <target> <name> [dynamic|debug]
rem   e.g.  common\build_plugin.bat zone void_bag
rem         common\build_plugin.bat character char_void
rem
rem Builds <target>\plugins\<name>\<name>.cpp into build\plugins\<name>.dll, with the shared library
rem (common\include) and the target's own headers (<target>\include) on the include path. Deploy the DLL
rem into the server's hooks\ folder beside that exe (Zone0X\hooks\, Character\hooks\).
rem
rem FULL CRT. The loader loads plugins from the SERVICE thread, long after loader init, so a plugin is an
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
cd /d "%~dp0.."

if "%~2"=="" (
  echo usage: common\build_plugin.bat ^<target^> ^<name^> [dynamic^|debug]
  echo   plugins:
  for %%t in (zone character) do for /d %%d in (%%t\plugins\*) do echo     %%t %%~nxd
  exit /b 1
)
set SRC=%~1\plugins\%~2\%~2.cpp
if not exist "%SRC%" (
  echo No such plugin: %SRC%
  exit /b 1
)

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat
if not exist "%VCVARS%" (
  echo Cannot find vcvars32.bat at "%VCVARS%" - edit VCVARS in this file.
  echo It must be the 32-BIT environment: the server exes are PE32.
  exit /b 1
)
call "%VCVARS%" >nul 2>&1

set OUT=build\plugins
set OBJ=build\obj\%~2
if not exist %OUT% mkdir %OUT%
if not exist %OBJ% mkdir %OBJ%
set INC=/I common\include /I %~1\include
set FLAGS=/nologo /W4 /EHsc /std:c++17 /O2 /MT %INC% /Fo%OBJ%\ /Fd%OUT%\%~2.pdb
if /i "%~3"=="dynamic" set FLAGS=/nologo /W4 /EHsc /std:c++17 /O2 /MD %INC% /Fo%OBJ%\ /Fd%OUT%\%~2.pdb
if /i "%~3"=="debug" set FLAGS=/nologo /W4 /EHsc /std:c++17 /Od /Zi /MTd %INC% /Fo%OBJ%\ /Fd%OUT%\%~2.pdb

cl %FLAGS% /LD "%SRC%" /link /OUT:%OUT%\%~2.dll /DEBUG /SUBSYSTEM:WINDOWS kernel32.lib user32.lib
if errorlevel 1 exit /b 1

echo.
echo   %OUT%\%~2.dll
echo.
echo Deploy: into the hooks\ folder beside the patched %~1 exe (fiestahook.dll sits beside the exe itself).
