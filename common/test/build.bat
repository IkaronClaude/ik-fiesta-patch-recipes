@echo off
rem Build and run the hook self-test as a plain 32-bit exe (no Zone.exe needed).
rem   common\test\build.bat      -> build\test_hook.exe, then runs it; exit code 1 on any failure
setlocal
cd /d "%~dp0"
set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat
if not exist "%VCVARS%" (
  echo Cannot find vcvars32.bat at %VCVARS% - edit VCVARS in this file, 32-BIT environment
  exit /b 1
)
call "%VCVARS%" >nul 2>&1
set OUT=..\..\build
set OBJ=..\..\build\obj\test
if not exist %OUT% mkdir %OUT%
if not exist %OBJ% mkdir %OBJ%
cl /nologo /W4 /EHsc /std:c++17 /DZH_NO_ODS /DWIN32_LEAN_AND_MEAN /I ..\include /Fo%OBJ%\ /Fe%OUT%\test_hook.exe test_hook.cpp /link user32.lib kernel32.lib advapi32.lib || exit /b 1
%OUT%\test_hook.exe
