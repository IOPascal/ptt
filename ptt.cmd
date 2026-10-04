@echo off
rem PTT starter for Windows: runs the tool from this checkout.
set "PTT_DIR=%~dp0"
set "PYTHONPATH=%PTT_DIR%;%PYTHONPATH%"
py -m ptt %*
