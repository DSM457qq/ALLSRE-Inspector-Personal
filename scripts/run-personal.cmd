@echo off
setlocal
cd /d "%~dp0.."
if not defined ALLSRE_INSPECTOR_CONFIG set "ALLSRE_INSPECTOR_CONFIG=%CD%\inspector.yaml"
".venv\Scripts\python.exe" -m allsre_inspector.personal.main --config "%ALLSRE_INSPECTOR_CONFIG%"
