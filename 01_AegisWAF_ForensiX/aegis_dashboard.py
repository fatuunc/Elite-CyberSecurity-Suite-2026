#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisWAF-ForensiX | Enterprise Adli Bilisim ve WAF Bypass Tespit Konsolu
Gelistirici: Fatih Tunc (Digital Forensics & Network Security Engineering)
Standartlar: CMK m.134, ISO/IEC 27037, RFC 3161 TSA, JA4/JA4H Fingerprinting
"""
import os
import sys
import time
import json
import streamlit as st
from aegis_engine import AegisForensiXEngine, MicroPcapWriter

st.set_page_config(
    page_title="AegisWAF-ForensiX | Fatih Tunc",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom styling for high-tech cybersec look
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px;
        color: #f8fafc;
    }
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-clean {
        background-color: #10b981;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if "engine" not in st.session_state:
    eng = AegisForensiXEngine()
    # Preload sample historical attacks
    b1 = '{"user": "fatih", "access": "readonly", "access": "root_admin\' OR 1=1--"}'
    r1 = f"POST /api/v1/privilege HTTP/1.1\r\nHost: core.network.local\r\nContent-Length: {len(b1)}\r\n\r\n{b1}".encode()
    eng.inspect_request("185.220.101.42", 51234, "t13d1516h2_8daaf6152771_e5627efa2ab1", "POST", "1.1", {"Host": "core.network.local"}, r1, b1)

    b2 = "0\r\n\r\nGPOST /admin/delete_user HTTP/1.1\r\nHost: waf.kurum.local\r\n\r\n"
    r2 = f"POST /search HTTP/1.1\r\nHost: waf.kurum.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n{body2 if 'body2' in locals() else b2}".encode()
    eng.inspect_request("194.26.192.77", 49120, "t13d1516h2_8daaf6152771_b186095e22b6", "POST", "1.1", {"Host": "waf.kurum.local", "Transfer-Encoding": "chunked"}, r2, b2)

    st.session_state.engine = eng

engine = st.session_state.engine

# Header
st.title("🛡️ AegisWAF-ForensiX: eBPF WAF Bypass & Adli Kanıt Zinciri")
st.caption("🚀 **Geliştirici:** Fatih Tunç | **Standartlar:** CMK m.134 & ISO/IEC 27037 Uyumlu SHA3-512 Merkle Zinciri & RFC 3161 TSA")

# Top KPI Metrics
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
with kpi1:
    st.metric("Toplam Yakalanan Kapsül", len(engine.evidence_vault))
with kpi2:
    st.metric("Merkle Zincir Durumu", "KIRILMAZ (GENESIS BAĞLI)", delta="SHA3-512")
with kpi3:
    st.metric("Kriptografik Zaman Damgası", "RFC 3161 TSA", delta="HMAC-SHA3-256")
with kpi4:
    st.metric("Ağ Seviyesi İnceleme", "eBPF / XDP Ready", delta="MicroPCAP")

st.markdown("---")

# Main Content Layout
col_left, col_right = st.columns([1.1, 0.9])

with col_left:
    st.subheader("🔬 Canlı WAF Atlatma & Desync Simülatörü")
    
    # Preset Selection
    preset = st.selectbox(
        "⚡ Hazır Saldırı Senaryosu Seç:",
        [
            "1. JSON Duplicate Key & NFKC Homoglyph Smuggling",
            "2. HTTP Request Smuggling (CL.TE Desync)",
            "3. Double URL Encoding & Overlong UTF-8 Directory Traversal",
            "4. Yüksek Entropili Gizli Shellcode Enjeksiyonu",
            "5. Temiz & Standart HTTP/1.1 İsteği",
            "6. Özel Manuel Saldırı Yükü (Custom)"
        ]
    )

    # Defaults based on preset
    if preset.startswith("1."):
        def_ip = "185.220.101.42"
        def_ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
        def_headers = "POST /api/v2/auth HTTP/1.1\r\nHost: waf.kurum.local\r\nContent-Type: application/json\r\nContent-Length: 72"
        def_body = '{"role": "citizen", "role": "system_admin\uff07 UNION SELECT password FROM users--"}'
    elif preset.startswith("2."):
        def_ip = "194.26.192.77"
        def_ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
        def_headers = "POST /transfer HTTP/1.1\r\nHost: banka.kurum.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked"
        def_body = "0\r\n\r\nGPOST /admin/exec_command?cmd=whoami HTTP/1.1\r\nHost: banka.kurum.local\r\n\r\n"
    elif preset.startswith("3."):
        def_ip = "45.154.255.89"
        def_ja4 = "t13d1516h2_8daaf6152771_f448c9012a99"
        def_headers = "GET /vulnerabilities/fi/?file=%252e%252e%252f%c0%afetc%c0%afshadow HTTP/1.1\r\nHost: secure.internal.local\r\nAccept: */*"
        def_body = ""
    elif preset.startswith("4."):
        def_ip = "91.240.118.15"
        def_ja4 = "t13d1516h2_8daaf6152771_a773bc9281e0"
        def_headers = "POST /api/upload HTTP/1.1\r\nHost: sec.local\r\nContent-Type: application/octet-stream"
        def_body = "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80" * 8
    elif preset.startswith("5."):
        def_ip = "10.0.4.15"
        def_ja4 = "t13d1516h2_8daaf6152771_9918237461aa"
        def_headers = "GET /index.html HTTP/1.1\r\nHost: public.web.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html"
        def_body = ""
    else:
        def_ip = "127.0.0.1"
        def_ja4 = "t13d1516h2_000000000000_000000000000"
        def_headers = "POST /api HTTP/1.1\r\nHost: example.com"
        def_body = "{}"

    c_ip, c_port = st.columns([3, 1])
    with c_ip:
        client_ip = st.text_input("Saldırgan Kaynak IP (IPv4):", def_ip)
    with c_port:
        client_port = st.number_input("Port:", min_value=1, max_value=65535, value=54120)

    ja4_fp = st.text_input("JA4 TLS ClientHello Parmak İzi:", def_ja4)
    raw_headers = st.text_area("Ham HTTP İstek Başlıkları:", def_headers, height=120)
    json_payload = st.text_area("HTTP Gövdesi / Yük:", def_body, height=100)

    if st.button("🚀 Paketi İncele ve Adli Kanıt Kapsülü Üret", use_container_width=True, type="primary"):
        t_start = time.perf_counter()
        full_raw = (raw_headers + ("\r\n\r\n" if json_payload else "\r\n\r\n") + json_payload).encode("latin-1")
        
        # Parse headers to dict
        lines = raw_headers.splitlines()
        req_line = lines[0] if lines else "GET / HTTP/1.1"
        parts = req_line.split(" ")
        mth = parts[0] if len(parts) > 0 else "GET"
        ver = parts[2].replace("HTTP/", "") if len(parts) > 2 else "1.1"
        h_dict = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                h_dict[k.strip()] = v.strip()

        cap = engine.inspect_request(client_ip, client_port, ja4_fp, mth, ver, h_dict, full_raw, json_payload)
        t_duration = (time.perf_counter() - t_start) * 1e6

        if cap:
            st.error(f"🚨 **WAF ATLATMA / BYPASS YAKALANDI!** (İnceleme Gecikmesi: {t_duration:.1f} µs)")
            st.markdown(f"**Vaka ID:** `{cap['case_id']}` | **Tehdit Derecesi:** <span class='badge-critical'>{cap['severity']}</span>", unsafe_allow_html=True)
            st.warning(f"**Tespit Edilen Atlatma Vektörü:**\n{cap['evasion_vector']}")
            st.info(f"**Shannon Entropisi:** `{cap['shannon_entropy']} bits/byte` | **Ayrıştırıcı Sapma Skoru:** `{cap['parser_delta_score']}`")
            with st.expander("📦 Tam Adli Kapsül JSON Detayı"):
                st.json(cap)
        else:
            st.success(f"✅ **PAKET TEMİZ.** Herhangi bir WAF bypass veya desync anomalisi saptanmadı. (Gecikme: {t_duration:.1f} µs)")

with col_right:
    st.subheader("⛓️ SHA3-512 Merkle Adli Kanıt Zinciri")
    
    ok, msg = engine.verify_merkle_chain_integrity()
    if ok:
        st.success(f"🔒 **Bütünlük Doğrulandı:** {msg}")
    else:
        st.error(f"⚠️ **Bütünlük Bozuldu:** {msg}")

    # Evidence Vault Items
    st.markdown(f"**Kayıtlı Adli Kapsül Sayısı:** `{len(engine.evidence_vault)}`")
    for cap in reversed(engine.evidence_vault):
        with st.expander(f"📦 {cap.case_id} | {cap.client_ip} | {cap.severity}", expanded=(cap == engine.evidence_vault[-1])):
            st.write(f"**Zaman (UTC):** `{cap.iso_timestamp}`")
            st.write(f"**JA4 TLS Fingerprint:** `{cap.ja4_tls_fingerprint}`")
            st.write(f"**JA4H HTTP Fingerprint:** `{cap.ja4h_http_fingerprint}`")
            st.write(f"**Atlatma Vektörü:** `{cap.evasion_vector}`")
            st.code(
                f"Önceki Hash : {cap.previous_capsule_hash}\n"
                f"Kapsül Hash : {cap.capsule_sha3_512}\n"
                f"RFC3161 TSA : {cap.rfc3161_tsa_token}",
                language="text"
            )

    st.markdown("---")
    st.subheader("💾 Adli Delil Dışa Aktarımı (CMK m.134)")
    
    # Export bundle on the fly
    os.makedirs("artifacts", exist_ok=True)
    json_path = os.path.join("artifacts", "forensic_evidence_vault.json")
    pcap_path = os.path.join("artifacts", "captured_waf_bypass_evidence.pcap")
    engine.export_forensic_bundle(json_path, pcap_path)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                st.download_button(
                    label="📄 JSON Kanıt Raporunu İndir",
                    data=f.read(),
                    file_name="forensic_evidence_vault.json",
                    mime="application/json",
                    use_container_width=True
                )
    with col_btn2:
        if os.path.exists(pcap_path):
            with open(pcap_path, "rb") as f:
                st.download_button(
                    label="🦈 MicroPCAP Ağ İzini İndir",
                    data=f.read(),
                    file_name="captured_waf_bypass_evidence.pcap",
                    mime="application/vnd.tcpdump.pcap",
                    use_container_width=True
                )
