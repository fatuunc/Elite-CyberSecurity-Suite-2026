@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
color 0B
title Fatih Tunç - Elite CyberSecurity Suite 2026 Master Launcher

:MENU
cls
echo ===============================================================================
echo   ______ _ _ _         _____        _               _____            
echo  ^|  ____^| ^| ^(_)       / ____^|      ^| ^|             / ____^|           
echo  ^| ^|__  ^| ^| ^|_ _____ ^| ^|    _   _ ^| ^|__   ___ _ __^| (___   ___  ___ 
echo  ^|  __^| ^| ^| ^| ^|____/ ^| ^|   ^| ^| ^| ^|^| '_ \ / _ \ '__^\___ \ / _ \/ __^|
echo  ^| ^|____^| ^| ^| ^|      ^| ^|___^| ^|_^| ^|^| ^|_) ^|  __/ ^|   ____) ^|  __/ (__ 
echo  ^|______^|_^|_^|_^|       \_____\__, ^|^|_.__/ \___^|_^|  ^|_____/ \___^|\___^|
echo                             __/ ^|                                        
echo                            ^|___/                                         
echo ===============================================================================
echo   FATİH TUNÇ - ELITE CYBERSECURITY & DIGITAL FORENSICS SUITE 2026
echo   Standartlar: CMK m.134 ^| ISO/IEC 27037 ^| RFC 3161 TSA ^| ENFSI Best Practice
echo ===============================================================================
echo.
echo   [1] 🛡️  AegisWAF-ForensiX Adli Bilişim ^& WAF Bypass Paneli (Streamlit)
echo   [2] 📸 Fotoİz-PRNU v2.0 Pro Sensör Biyometrisi ^& Isı Haritası (Streamlit)
echo   [3] 🐘 PgWal-Phantom PostgreSQL Binary Heap Carver Paneli (Streamlit)
echo   [4] 🛡️  .NET 10 EF Core Zero-Trust AST Interceptor (Konsol Demosu)
echo   [5] 🌐 Master Suite Birleşik Forensic Konsolu (Streamlit Hub)
echo   [6] 🧪 Tüm Modüller İçin Otomatize Test Koşucusunu Başlat (Test Runner)
echo   [7] 📦 Python Bağımlılıklarını Doğrula / Yükle (pip install -r requirements)
echo   [0] ❌ Çıkış
echo.
echo ===============================================================================
set /p CHOICE="Lütfen çalıştırmak istediğiniz seçeneği girin [0-7]: "

if "%CHOICE%"=="1" goto RUN_AEGIS
if "%CHOICE%"=="2" goto RUN_FOTOIZ
if "%CHOICE%"=="3" goto RUN_PGWAL
if "%CHOICE%"=="4" goto RUN_DOTNET
if "%CHOICE%"=="5" goto RUN_HUB
if "%CHOICE%"=="6" goto RUN_TESTS
if "%CHOICE%"=="7" goto RUN_PIP
if "%CHOICE%"=="0" goto EXIT
goto MENU

:RUN_AEGIS
echo.
echo [*] AegisWAF-ForensiX Streamlit Paneli Başlatılıyor...
start "AegisWAF-ForensiX" streamlit run 01_AegisWAF_ForensiX\aegis_dashboard.py
goto MENU

:RUN_FOTOIZ
echo.
echo [*] Fotoİz-PRNU v2.0 Pro Streamlit Paneli Başlatılıyor...
start "Fotoİz-PRNU v2.0 Pro" streamlit run 02_FotoIz_PRNU_v2_Pro\app_streamlit.py
goto MENU

:RUN_PGWAL
echo.
echo [*] PgWal-Phantom PostgreSQL Heap Carver Streamlit Paneli Başlatılıyor...
start "PgWal-Phantom" streamlit run 03_PgWal_Phantom\app_streamlit.py
goto MENU

:RUN_DOTNET
echo.
echo [*] .NET 10 EF Core Zero-Trust AST Guard Çalıştırılıyor...
cd /d "%~dp003_PgWal_Phantom\DotNet10_EFCore_AST_Guard"
dotnet run
cd /d "%~dp0"
echo.
pause
goto MENU

:RUN_HUB
echo.
echo [*] Master Suite Birleşik Konsol Hub Başlatılıyor...
start "Elite CyberSecurity Suite Hub" streamlit run master_hub.py
goto MENU

:RUN_TESTS
echo.
echo [*] Entegre Doğrulama Testleri Çalıştırılıyor...
python test_runner.py
echo.
pause
goto MENU

:RUN_PIP
echo.
echo [*] requirements.txt Paketleri Yükleniyor...
pip install -r requirements.txt
echo.
pause
goto MENU

:EXIT
echo.
echo Güvenli günler dileriz!
exit /b 0
