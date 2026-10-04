@echo off
rem Build the bridge26 translator vector tool (32-bit, like the plugin): build\bridge26_vectors.exe
setlocal
cd /d "%~dp0"
set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat
call "%VCVARS%" >nul 2>&1
set OUT=..\..\..\..\build
if not exist %OUT%\obj\bridge26 mkdir %OUT%\obj\bridge26
cl /nologo /W4 /EHsc /std:c++17 /Fo%OUT%\obj\bridge26\ /Fe%OUT%\bridge26_vectors.exe bridge26_vectors.cpp || exit /b 1
echo   build\bridge26_vectors.exe
