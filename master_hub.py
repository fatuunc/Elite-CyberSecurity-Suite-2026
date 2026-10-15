#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fatih Tunç - Elite CyberSecurity Suite 2026 (Master Forensic Hub)
Birleşik Siber Güvenlik, Ağ Savunması ve Adli Bilişim Platformu
Modüller:
 1. AegisWAF-ForensiX: eBPF WAF Bypass & Adli Kanıt Zinciri
 2. Fotoİz-PRNU v2.0 Pro: Sensör Biyometrisi & Medya Arkeolojisi
 3. PgWal-Phantom & .NET 10 AST Guard: PostgreSQL Dead Tuple Carver & Zero-Trust Interceptor
"""
import os
import sys
import subprocess
import streamlit as st

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

st.set_page_config(
    page_title="Elite CyberSecurity Suite 2026 | Fatih Tunç",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .module-card {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 20px;
        height: 100%;
    }
    .module-title {
        color: #38bdf8;
        font-size: 1.3rem;
        font-weight: bold;
        margin-bottom: 8px;
    }
    .badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        margin-right: 5px;
        margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Fatih Tunç - Elite CyberSecurity Suite 2026")
st.caption("🚀 CMK m.134, ISO/IEC 27037 ve ENFSI Uyumlu Kurumsal Düzey Siber Güvenlik & Adli Bilişim Çözümleri")

st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class="module-card">
        <div class="module-title">🛡️ 01. AegisWAF-ForensiX</div>
        <div>
            <span class="badge" style="background-color: #0284c7; color: white;">eBPF / XDP</span>
            <span class="badge" style="background-color: #7c3aed; color: white;">SHA3-512 Merkle</span>
            <span class="badge" style="background-color: #059669; color: white;">RFC 3161 TSA</span>
        </div>
        <p>HTTP Request Smuggling (CL.TE/TE.CL), JSON Duplicate Key Evasion, NFKC Homoglyph Smuggling ve Overlong UTF-8 saldırılarını mikrosaniye seviyesinde tespit eder. Saldırgan paketini MicroPCAP olarak izole eder ve değiştirilemez adli kanıt zincirine (Merkle DAG) mühürler.</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("")
    st.info("💡 Çalıştırmak için: `RUN_01_AegisWAF.bat` veya terminalden `streamlit run 01_AegisWAF_ForensiX/aegis_dashboard.py`")

with col2:
    st.markdown("""
    <div class="module-card">
        <div class="module-title">📸 02. Fotoİz-PRNU v2.0 Pro</div>
        <div>
            <span class="badge" style="background-color: #ea580c; color: white;">CMOS PRNU</span>
            <span class="badge" style="background-color: #16a34a; color: white;">2D FFT PCE</span>
            <span class="badge" style="background-color: #d97706; color: white;">Solar Geometry</span>
        </div>
        <p>WhatsApp, Telegram gibi mecralarda tüm EXIF metaverileri silinmiş dahi olsa, fotoğrafın çekildiği fiziksel kamera sensörünü parmak izinden (PRNU) tespit eder (ENFSI Eşik: PCE ≥ 60.0). Kayan pencereli 2D ısı haritasıyla deepfake/splicing montaj bölgelerini koordinat bazında ortaya çıkarır.</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("")
    st.info("💡 Çalıştırmak için: `RUN_02_FotoIz.bat` veya terminalden `streamlit run 02_FotoIz_PRNU_v2_Pro/app_streamlit.py`")

with col3:
    st.markdown("""
    <div class="module-card">
        <div class="module-title">🐘 03. PgWal-Phantom & AST Guard</div>
        <div>
            <span class="badge" style="background-color: #2563eb; color: white;">Postgres 8KB Heap</span>
            <span class="badge" style="background-color: #dc2626; color: white;">MVCC Dead Tuples</span>
            <span class="badge" style="background-color: #4f46e5; color: white;">.NET 10 EF Core</span>
        </div>
        <p>Saldırganlar veritabanı saldırı loglarını silse bile (anti-forensics), 8KB ham heap sayfalarını bayt bayt kazıyarak (carving) silinmiş satırları (Dead Tuples) kurtarır. .NET 10 EF Core AST Command Interceptor ise sorguların soyut sözdizim ağacı (AST) parmak izini çıkarıp SQL injection saldırılarını veritabanına ulaşmadan bloklar.</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("")
    st.info("💡 Çalıştırmak için: `RUN_03_PgWal_Phantom.bat` veya `RUN_04_DotNet10_AST_Guard.bat`")

st.markdown("---")
st.subheader("⚡ Hızlı Test ve Doğrulama Merkezi")
st.write("Tüm modüllerin matematiksel motorlarını ve adli delil zincirlerini tek tıkla test edin:")

if st.button("🧪 Tüm Modüller İçin Entegre Test Koşusunu Başlat", type="primary", use_container_width=True):
    with st.spinner("Tüm adli motorlar doğrulanıyor..."):
        test_out = subprocess.run([sys.executable, "test_runner.py"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        st.code(test_out.stdout if test_out.stdout else test_out.stderr)
