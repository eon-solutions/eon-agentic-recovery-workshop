@echo off
cd /d "%~dp0"
uv run agent\main.py %*
