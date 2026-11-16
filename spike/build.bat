@echo off
rem Build the phase-0 spike.
rem Run from "x64 Native Tools Command Prompt for VS" (Visual Studio Build Tools with the C++ workload).
rem The client is 64-bit, so both outputs must be 64-bit.

cl /nologo /LD /MD /EHsc /O2 /W3 tuxtap.cpp /link /OUT:tuxtap.dll
if errorlevel 1 exit /b 1

cl /nologo /EHsc /O2 /W3 tuxtap-launch.cpp /link /OUT:tuxtap-launch.exe
if errorlevel 1 exit /b 1

echo Built tuxtap.dll and tuxtap-launch.exe
