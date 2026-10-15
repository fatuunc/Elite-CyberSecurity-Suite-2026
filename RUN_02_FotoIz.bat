@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
color 0E
title 📸 Fotoİz-PRNU v2.0 Pro Launcher (Fatih Tunç)
echo ===============================================================================
echo 📸 Fotoİz-PRNU v2.0 Pro: Sensör Biyometrisi ^& Medya Arkeolojisi
echo Geliştirici: Fatih Tunç
echo ===============================================================================
echo [*] Streamlit Dashboard Başlatılıyor...
cd /d "%~dp0"
streamlit run 02_FotoIz_PRNU_v2_Pro\app_streamlit.py
pause
