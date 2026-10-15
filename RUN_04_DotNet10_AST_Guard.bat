@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
color 0B
title 🛡️ .NET 10 EF Core Zero-Trust AST Guard (Fatih Tunç)
echo ===============================================================================
echo 🛡️  .NET 10 EF Core Zero-Trust AST Interceptor ^& SQLi Blocker
echo Geliştirici: Fatih Tunç
echo ===============================================================================
echo [*] .NET 10 Konsol Demosu Çalıştırılıyor...
cd /d "%~dp003_PgWal_Phantom\DotNet10_EFCore_AST_Guard"
dotnet run
pause
