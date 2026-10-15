@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
color 0A
title 🛡️ AegisWAF-ForensiX Launcher (Fatih Tunç)
echo ===============================================================================
echo 🛡️  AegisWAF-ForensiX: eBPF WAF Bypass ^& Adli Kanıt Zinciri
echo Geliştirici: Fatih Tunç
echo ===============================================================================
echo [*] Streamlit Dashboard Başlatılıyor...
cd /d "%~dp0"
streamlit run 01_AegisWAF_ForensiX\aegis_dashboard.py
pause
