#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PgWal-Phantom | PostgreSQL Low-Level Binary Heap & WAL Carver Adli Konsolu
Geliştirici: Fatih Tunç (Database Forensics & Anti-Forensics Reconstruction)
Standartlar: CMK m.134, ISO/IEC 27037, PostgreSQL MVCC Architecture (8KB Page Internals)
"""
import os
import sys
import json
import pandas as pd
import streamlit as st
from pgwal_heap_carver import PgWalPhantomCarver, build_synthetic_postgres_heap_file

st.set_page_config(
    page_title="PgWal-Phantom | Fatih Tunç",
    page_icon="🐘",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Cyber Forensic Styling
st.markdown("""
<style>
    .live-badge {
        background-color: #065f46;
        color: #d1fae5;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .dead-badge {
        background-color: #991b1b;
        color: #fee2e2;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

samples_dir = os.path.join(os.path.dirname(__file__), "forensic_samples")
os.makedirs(samples_dir, exist_ok=True)
default_heap_path = os.path.join(samples_dir, "pg_heap_relfilenode_16384.bin")

if not os.path.exists(default_heap_path):
    build_synthetic_postgres_heap_file(default_heap_path)

st.title("🐘 PgWal-Phantom: PostgreSQL Binary Heap & Dead Tuple Kurtarma")
st.caption("🚀 **Geliştirici:** Fatih Tunç | **Standartlar:** CMK m.134 Uyumlu Veritabanı Adli Bilişimi & MVCC Anti-Forensics Analizi")

# Sidebar
st.sidebar.header("📁 Veritabanı Dosyası Seçimi")
source_mode = st.sidebar.radio("Kaynak Seçin:", ["Hazır Adli Heap Dosyası (Saldırı İzleri)", "Özel PostgreSQL Heap Yükle (.bin)"])

if source_mode == "Hazır Adli Heap Dosyası (Saldırı İzleri)":
    target_heap = default_heap_path
    st.sidebar.info(f"Yüklü: `{os.path.basename(default_heap_path)}`")
else:
    uploaded = st.sidebar.file_uploader("PostgreSQL 8KB Sayfa Dosyası Yükleyin:", type=["bin", "dat", "raw"])
    if uploaded:
        temp_path = os.path.join(samples_dir, "uploaded_heap_temp.bin")
        with open(temp_path, "wb") as f:
            f.write(uploaded.read())
        target_heap = temp_path
        st.sidebar.success("Dosya yüklendi!")
    else:
        target_heap = default_heap_path

# Run Carver
with st.spinner("PostgreSQL 8KB Sayfa Başlıkları ve Line Pointer'lar Ayrıştırılıyor..."):
    results = PgWalPhantomCarver.carve_heap_file(target_heap)

# KPIs
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Taranan 8KB Sayfa", results["total_8kb_pages_scanned"])
with col2:
    st.metric("Aktif Canlı Kayıt (Live)", results["active_live_tuples_count"])
with col3:
    st.metric("🚨 Kurtarılan Silinmiş Kayıt (Dead)", results["recovered_deleted_tuples_count"], delta="Saldırgan İzleri", delta_color="inverse")
with col4:
    deleted_xids = list({r["t_xmax_deleted_xid"] for r in results["recovered_deleted_records"]})
    st.metric("Saldırgan İşlem ID (XID)", f"{deleted_xids[0] if deleted_xids else 'Yok'}")

st.markdown("---")

tab_carver, tab_timeline, tab_hex, tab_export = st.tabs([
    "🔍 1. Tuple & Line Pointer Analiz Tablosu",
    "⏳ 2. Saldırgan Zaman Çizelgesi (Timeline Reconstruction)",
    "🧩 3. Ham Hex & Adli İnceleme",
    "📥 4. CMK 134 Dışa Aktarım"
])

all_tuples = results["active_records"] + results["recovered_deleted_records"]

with tab_carver:
    st.subheader("🔍 Ayrıştırılan Tüm Kayıtlar (Canlı ve Silinmiş)")
    st.write("Saldırgan `DELETE FROM audit_logs` komutunu çalıştırsa dahi PostgreSQL, VACUUM tetiklenene kadar kayıtları sayfada (Heap) tutar. xmax değeri 0 olmayan ve HEAP_XMAX_INVALID biti temiz olan kayıtlar silinmiş adli kanıtlardır.")

    filter_option = st.radio("Filtrele:", ["Tümü", "Sadece Kurtarılan Silinmiş Kayıtlar (Dead Tuples)", "Sadece Canlı Kayıtlar (Live)"], horizontal=True)
    
    if filter_option == "Sadece Kurtarılan Silinmiş Kayıtlar (Dead Tuples)":
        display_tuples = results["recovered_deleted_records"]
    elif filter_option == "Sadece Canlı Kayıtlar (Live)":
        display_tuples = results["active_records"]
    else:
        display_tuples = all_tuples

    table_data = []
    for r in display_tuples:
        table_data.append({
            "Durum": "🚨 SİLİNMİŞ (DEAD)" if r["status"] == "DELETED_DEAD_TUPLE" else "✅ CANLI (LIVE)",
            "CTID": r["ctid"],
            "Oluşturan XID (xmin)": r["t_xmin_created_xid"],
            "Silen XID (xmax)": r["t_xmax_deleted_xid"] if r["t_xmax_deleted_xid"] != 0 else "-",
            "Bayt Boyutu": r["tuple_length_bytes"],
            "Kurtarılan İçerik (Payload)": r["carved_utf8_preview"]
        })
    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True, height=280)

with tab_timeline:
    st.subheader("⏳ Anti-Forensics Zaman Çizelgesi ve Olay Sıralaması")
    st.write("PostgreSQL MVCC XID sıralamasına göre saldırganın veritabanı üzerindeki adımları:")
    
    for r in results["recovered_deleted_records"]:
        with st.container():
            st.markdown(f"""
            <div style="border-left: 4px solid #ef4444; padding-left: 12px; margin-bottom: 12px;">
                <strong>Kurtarılan Silinmiş Kayıt ({r['ctid']})</strong> - Silen İşlem (xmax): <code>XID {r['t_xmax_deleted_xid']}</code><br>
                <strong>Ham Veri:</strong> <code>{r['carved_utf8_preview']}</code><br>
                <small style="color: #94a3b8;">Ofset: {r['tuple_byte_offset']} | Bayt: {r['tuple_length_bytes']} bytes</small>
            </div>
            """, unsafe_allow_html=True)

with tab_hex:
    st.subheader("🧩 8KB PostgreSQL Sayfası Ham Hex Görünümü")
    selected_tuple = st.selectbox("İncelenecek Kaydı Seçin (CTID):", [r["ctid"] + " - " + r["carved_utf8_preview"][:40] for r in all_tuples])
    sel_ctid = selected_tuple.split(" - ")[0]
    matched = [r for r in all_tuples if r["ctid"] == sel_ctid]
    if matched:
        m = matched[0]
        st.write(f"**CTID:** `{m['ctid']}` | **Status:** `{m['status']}`")
        st.write(f"**xmin:** `{m['t_xmin_created_xid']}` | **xmax:** `{m['t_xmax_deleted_xid']}` | **Sütun Sayısı:** `{m['column_count_natts']}`")
        st.text_area("Ham Hex Payload:", m["raw_payload_hex"], height=100)

with tab_export:
    st.subheader("📥 Adli Kanıt Dosyaları ve Bilirkişi Raporu")
    json_bytes = json.dumps(results, indent=2, ensure_ascii=False).encode("utf-8")
    
    # CSV export
    csv_str = df.to_csv(index=False)
    
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        st.download_button(
            label="📄 Kurtarılan Delilleri JSON Olarak İndir",
            data=json_bytes,
            file_name="pgwal_carved_evidence.json",
            mime="application/json",
            use_container_width=True
        )
    with col_e2:
        st.download_button(
            label="📊 Kurtarılan Delilleri CSV Olarak İndir",
            data=csv_str,
            file_name="pgwal_carved_evidence.csv",
            mime="text/csv",
            use_container_width=True
        )
