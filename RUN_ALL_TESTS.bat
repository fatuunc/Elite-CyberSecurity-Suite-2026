@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
color 0F
title 🧪 Elite CyberSecurity Suite - Automated Test Runner
echo ===============================================================================
echo 🧪 Elite CyberSecurity Suite - Otomatize Doğrulama Testleri
echo ===============================================================================
cd /d "%~dp0"
python test_runner.py
pause
