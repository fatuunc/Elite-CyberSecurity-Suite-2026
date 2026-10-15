@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
color 0C
title 🐘 PgWal-Phantom Heap Carver Launcher (Fatih Tunç)
echo ===============================================================================
echo 🐘 PgWal-Phantom: PostgreSQL Binary Heap Carver ^& Dead Tuple Recovery
echo Geliştirici: Fatih Tunç
echo ===============================================================================
echo [*] Streamlit Dashboard Başlatılıyor...
cd /d "%~dp0"
streamlit run 03_PgWal_Phantom\app_streamlit.py
pause
