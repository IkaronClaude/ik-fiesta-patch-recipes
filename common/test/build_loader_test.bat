@echo off
rem The loader's hooks\<name>.ini rules (enabled / after / [config]) on dummy plugins. Must print PASS.
setlocal
cd /d "%~dp0"
set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat
call "%VCVARS%" >nul 2>&1
set OUT=..\..\build\test_loader
set OBJ=..\..\build\obj\test_loader
if exist %OUT% rmdir /s /q %OUT%
mkdir %OUT%
if not exist %OBJ% mkdir %OBJ%
cl /nologo /W3 /EHsc /std:c++17 /LD /DWIN32_LEAN_AND_MEAN /I ..\include /Fo%OBJ%\ /Fe%OUT%\loader_dummy.dll loader_dummy.cpp /link kernel32.lib user32.lib || exit /b 1
cl /nologo /W3 /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /DWIN32_LEAN_AND_MEAN /I ..\include /Fo%OBJ%\ /Fe%OUT%\test_loader.exe test_loader.cpp /link kernel32.lib user32.lib || exit /b 1
cd /d %OUT%
test_loader.exe
