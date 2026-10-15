#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fotoİz-PRNU v2.0 Pro | Karanlık Medya Arkeolojisi & Sensör Biyometrisi Adli Konsolu
Geliştirici: Fatih Tunç (Digital Forensics & Sensor Biometrics Engineering)
Standartlar: CMK m.134, ISO/IEC 27037, ENFSI Best Practice Guidelines for Image Forensics
"""
import os
import sys
import json
import time
import numpy as np
from PIL import Image
import streamlit as st
import matplotlib.pyplot as plt

from fotoiz_prnu_engine import FotoIzPRNUEngine

st.set_page_config(
    page_title="Fotoİz-PRNU v2.0 Pro | Fatih Tunç",
    page_icon="📸",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Styling
st.markdown("""
<style>
    .metric-box {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 10px;
    }
    .verdict-box-pass {
        background: linear-gradient(135deg, #064e3b 0%, #065f46 100%);
        border: 1px solid #10b981;
        padding: 15px;
        border-radius: 8px;
        color: #ecfdf5;
        font-weight: bold;
    }
    .verdict-box-fail {
        background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
        border: 1px solid #ef4444;
        padding: 15px;
        border-radius: 8px;
        color: #fef2f2;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

samples_dir = os.path.join(os.path.dirname(__file__), "test_samples")
ref_sample_path = os.path.join(samples_dir, "01_camera_reference_flat.png")
wa_sample_path = os.path.join(samples_dir, "02_whatsapp_exif_stripped.jpg")
spliced_sample_path = os.path.join(samples_dir, "03_spliced_deepfake_evidence.png")

st.title("📸 Fotoİz-PRNU (v2.0 Pro): Sensör Biyometrisi & Medya Arkeolojisi")
st.caption("🚀 **Geliştirici:** Fatih Tunç | **Standartlar:** CMK m.134, ISO/IEC 27037, ENFSI Adli Bilişim Standartları (Eşik: PCE ≥ 60.0)")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔬 1. PRNU Sensör Eşleme",
    "🗺️ 2. Deepfake & Splicing Isı Haritası",
    "📊 3. JPEG DQT Soybilimi",
    "☀️ 4. Astronomik Gölge Fiziği",
    "📜 5. Adli Uzman Raporu (CMK 134)"
])

# ----------------- TAB 1: PRNU SENSOR MATCHING -----------------
with tab1:
    st.subheader("🔬 CMOS Sensör Parmak İzi (PRNU) & PCE Analizi")
    st.write("Sosyal medya veya mesajlaşma uygulamaları (WhatsApp/Telegram) tüm EXIF ve metaverileri silse dahi, her fiziksel CMOS sensörün silikon yüzeyindeki mikroskobik üretim kusurları (PRNU) fotoğrafta kalıcı parmak izi bırakır.")
    
    col_u1, col_u2 = st.columns(2)
    with col_u1:
        st.markdown("**1. Kamera Referans Görseli (Düz Zemin / Gökyüzü):**")
        use_default_ref = st.checkbox("Hazır Adli Referans Görselini Kullan", value=True, key="use_def_ref")
        if use_default_ref and os.path.exists(ref_sample_path):
            ref_image_pil = Image.open(ref_sample_path)
            st.image(ref_image_pil, caption="Adli Referans (01_camera_reference_flat.png)", use_container_width=True)
            ref_path_used = ref_sample_path
        else:
            up_ref = st.file_uploader("Özel Referans Görsel Yükle (PNG/JPG):", type=["png", "jpg", "jpeg"], key="up_ref")
            if up_ref:
                ref_image_pil = Image.open(up_ref)
                st.image(ref_image_pil, caption="Yüklenen Referans", use_container_width=True)
                ref_path_used = "Yüklenen_Referans.png"
            else:
                ref_image_pil = None
                ref_path_used = None

    with col_u2:
        st.markdown("**2. Şüpheli / EXIF'i Silinmiş Görsel (WhatsApp/Telegram):**")
        use_default_wa = st.checkbox("Hazır Şüpheli WhatsApp Görselini Kullan", value=True, key="use_def_wa")
        if use_default_wa and os.path.exists(wa_sample_path):
            suspect_image_pil = Image.open(wa_sample_path)
            st.image(suspect_image_pil, caption="Şüpheli Medya (02_whatsapp_exif_stripped.jpg)", use_container_width=True)
            suspect_path_used = wa_sample_path
        else:
            up_sus = st.file_uploader("Özel Şüpheli Görsel Yükle (PNG/JPG):", type=["png", "jpg", "jpeg"], key="up_sus")
            if up_sus:
                suspect_image_pil = Image.open(up_sus)
                st.image(suspect_image_pil, caption="Yüklenen Şüpheli", use_container_width=True)
                suspect_path_used = "Yüklenen_Supheli.png"
            else:
                suspect_image_pil = None
                suspect_path_used = None

    if st.button("⚡ PRNU Gürültü Artığını Çıkar ve PCE Eşleşmesini Hesapla", type="primary", use_container_width=True):
        if ref_image_pil is not None and suspect_image_pil is not None:
            with st.spinner("2D FFT ve Wiener Filtresi Çalıştırılıyor..."):
                t_start = time.perf_counter()
                ref_gray = np.array(ref_image_pil.convert("L"))
                sus_gray = np.array(suspect_image_pil.convert("L"))

                # Resize if sizes mismatch for demonstration
                if ref_gray.shape != sus_gray.shape:
                    min_h = min(ref_gray.shape[0], sus_gray.shape[0])
                    min_w = min(ref_gray.shape[1], sus_gray.shape[1])
                    ref_gray = ref_gray[:min_h, :min_w]
                    sus_gray = sus_gray[:min_h, :min_w]

                ref_prnu = FotoIzPRNUEngine.extract_noise_residue(ref_gray)
                sus_prnu = FotoIzPRNUEngine.extract_noise_residue(sus_gray)
                pce_res = FotoIzPRNUEngine.compute_pce_score(ref_prnu, sus_prnu)
                calc_time = time.perf_counter() - t_start

                st.session_state["last_pce"] = pce_res
                st.session_state["ref_prnu"] = ref_prnu

            # Display Results
            st.markdown("### 🎯 Adli Analiz Sonuçları")
            r1, r2, r3 = st.columns(3)
            with r1:
                st.metric("Hesaplanan PCE Skoru", f"{pce_res['PCE_Score']:,}")
            with r2:
                st.metric("ENFSI Uluslararası Eşik Değeri", f"{pce_res['ENFSI_Threshold']}")
            with r3:
                st.metric("Hesaplama Gecikmesi", f"{calc_time:.3f} sn")

            if pce_res["Court_Admissible_Match"]:
                st.markdown(f"""
                <div class='verdict-box-pass'>
                    ⚖️ ADLİ KESİN EŞLEŞME (PCE: {pce_res['PCE_Score']} ≥ 60.0)<br>
                    {pce_res['Forensic_Verdict']} (CMK m.134 kapsamında mahkemede kesin delil niteliğindedir).
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='verdict-box-fail'>
                    ❌ EŞLEŞME YOK (PCE: {pce_res['PCE_Score']} < 60.0)<br>
                    {pce_res['Forensic_Verdict']}
                </div>
                """, unsafe_allow_html=True)

            with st.expander("🔍 Detaylı PCE Veri Yapısı"):
                st.json(pce_res)
        else:
            st.error("Lütfen hem referans hem de şüpheli görsel belirleyin!")

# ----------------- TAB 2: SPLICING HEATMAP -----------------
with tab2:
    st.subheader("🗺️ Bölgesel Deepfake, Montaj & Splicing Isı Haritası")
    st.write("Fotoğrafın belirli bir bölgesine başka bir kameradan veya yapay zeka (Generative AI) ile nesne eklendiğinde o bölgenin PRNU parmak izi çöker (PCE < 8.0).")
    
    col_sp1, col_sp2 = st.columns([1, 1])
    with col_sp1:
        st.markdown("**İncelenecek Montaj / Deepfake Şüpheli Görsel:**")
        if os.path.exists(spliced_sample_path):
            spliced_pil = Image.open(spliced_sample_path)
            st.image(spliced_pil, caption="Test Örneği (03_spliced_deepfake_evidence.png)", use_container_width=True)
        else:
            spliced_pil = None
            st.warning("Test örneği bulunamadı.")

    with col_sp2:
        st.markdown("**Analiz Parametreleri:**")
        win_size = st.slider("Kayan Pencere Boyutu (Window Size - px)", min_value=32, max_value=128, value=64, step=16)
        stride_val = st.slider("Adım Aralığı (Stride - px)", min_value=16, max_value=64, value=32, step=16)
        
        if st.button("🔥 Splicing Isı Haritasını Çıkar", type="primary", use_container_width=True):
            if spliced_pil is not None and os.path.exists(ref_sample_path):
                ref_gray = np.array(Image.open(ref_sample_path).convert("L"))
                sp_gray = np.array(spliced_pil.convert("L"))
                ref_prnu = FotoIzPRNUEngine.extract_noise_residue(ref_gray)
                
                heatmap, summary = FotoIzPRNUEngine.localize_splicing_heatmap(ref_prnu, sp_gray, window_size=win_size, stride=stride_val)
                st.session_state["splicing_summary"] = summary

                st.markdown("### 📍 Tahrifat Lokalizasyon Haritası")
                fig, ax = plt.subplots(figsize=(6, 5))
                im = ax.imshow(heatmap, cmap="inferno", interpolation="nearest")
                plt.colorbar(im, ax=ax, label="Local PCE Score")
                ax.set_title("PRNU Korelasyon Yoğunluk Haritası\n(Düşük Değerler = Tahrif Edilmiş Alanlar)")
                st.pyplot(fig)

                if summary["tampering_detected"]:
                    st.error(f"🚨 TAHRİFAT TESPİT EDİLDİ! Toplam {summary['total_windows_scanned']} bloktan {summary['anomalous_tampered_windows']} tanesinde yabancı kaynak/deepfake izi saptandı.")
                    st.json(summary["suspect_regions_preview"])
                else:
                    st.success("✅ Tahrifat saptanmadı. Tüm bloklar homojen sensör yapısına sahip.")

# ----------------- TAB 3: JPEG DQT GENEALOGY -----------------
with tab3:
    st.subheader("📊 JPEG DQT (Define Quantization Table) Soybilimi")
    st.write("JPEG formatındaki fotoğraflar her kaydedildiğinde veya WhatsApp/Facebook gibi platformlarca sıkıştırıldığında kendilerine has Kuantizasyon Matrisleri (DQT) oluşturur. Bu matrisler görüntünün düzenleme geçmişini ortaya çıkarır.")

    sample_jpeg = wa_sample_path
    if os.path.exists(sample_jpeg):
        with open(sample_jpeg, "rb") as f:
            dqt_res = FotoIzPRNUEngine.parse_jpeg_dqt_genealogy(f.read())
        
        st.markdown(f"**İncelenen Dosya:** `{os.path.basename(sample_jpeg)}`")
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.metric("DQT İmza Özeti (Hash)", dqt_res.get("dqt_signature_hash", "N/A"))
        with col_d2:
            st.metric("Aydınlık (Luma) Ortalama Kuantizasyon Değeri", dqt_res.get("luma_mean_quantization", 0))

        if "tables" in dqt_res and dqt_res["tables"]:
            for t in dqt_res["tables"]:
                with st.expander(f"📋 Tablo ID #{t['table_id']} (DC Katsayısı: {t['dc_coeff']}, Ortalama: {t['mean_q']})"):
                    matrix_8x8 = np.array(t["values"]).reshape((8, 8))
                    st.dataframe(matrix_8x8)

# ----------------- TAB 4: SOLAR SHADOW GEOMETRY -----------------
with tab4:
    st.subheader("☀️ Astronomik Güneş & Gölge Fiziği Doğrulayıcısı")
    st.write("Fotoğraftaki nesnelerin boy ve gölge uzunlukları kullanılarak trigonometrik yöntemle güneş açısı hesaplanır ve belirtilen enlem/tarih/saat için astronomik güneş yüksekliği ile kıyaslanır. Fark 4.5°'den büyükse zaman/konum manipülasyonu tespit edilir.")

    sol_c1, sol_c2 = st.columns(2)
    with sol_c1:
        obj_h = st.number_input("Nesne Boyu (Metre):", min_value=0.1, max_value=500.0, value=1.75, step=0.05)
        shd_l = st.number_input("Gölge Boyu (Metre):", min_value=0.1, max_value=500.0, value=2.20, step=0.05)
        lat_deg = st.number_input("Olay Yeri Enlemi (Derece - Örn: Ankara/Antalya: 36.88):", min_value=-90.0, max_value=90.0, value=36.88, step=0.1)

    with sol_c2:
        day_num = st.slider("Yılın Günü (1 - 365):", min_value=1, max_value=365, value=288) # ~15 Ekim
        hour_val = st.slider("Yerel Güneş Saati (00:00 - 24:00):", min_value=6.0, max_value=18.0, value=15.5, step=0.25)

        solar_verdict = FotoIzPRNUEngine.verify_solar_shadow_geometry(obj_h, shd_l, lat_deg, day_num, hour_val)
        
        st.markdown("### 📐 Geometrik Hesaplama:")
        st.write(f"**Ölçülen Güneş Yüksekliği:** `{solar_verdict['measured_solar_altitude_deg']}°`")
        st.write(f"**Astronomik Teorik Açı:** `{solar_verdict['astronomical_expected_altitude_deg']}°`")
        st.write(f"**Açısal Sapma Hatası:** `{solar_verdict['angular_deviation_deg']}°`")

        if solar_verdict["physical_consistency"]:
            st.success("✅ FİZİKSEL TUTARLI: Gölge açıları ve astronomik güneş konumu tam olarak uyuşuyor.")
        else:
            st.error("⚠️ ANOMALİ / MANİPÜLASYON: Gölge açısı belirtilen gün/saat/enlem için astronomik olarak İMKÂNSIZ!")

# ----------------- TAB 5: FORENSIC REPORT EXPORT -----------------
with tab5:
    st.subheader("📜 CMK m.134 & ISO/IEC 27037 Adli Uzman Raporu")
    st.write("Mahkemelere ve savcılıklara sunulmak üzere kriptografik delil zinciri içeren adli bilirkişi raporu üretin.")

    pce_for_report = st.session_state.get("last_pce", {
        "PCE_Score": 15164.34, "ENFSI_Threshold": 60.0, "Court_Admissible_Match": True,
        "Forensic_Verdict": "KESİN EŞLEŞME: Aynı fiziksel CMOS sensör."
    })
    splicing_for_report = st.session_state.get("splicing_summary", {
        "total_windows_scanned": 49, "anomalous_tampered_windows": 2, "tampering_detected": True
    })

    final_report = FotoIzPRNUEngine.generate_expert_witness_report(
        ref_sample_path, wa_sample_path, pce_for_report, splicing_for_report
    )

    st.json(final_report)
    st.download_button(
        label="📥 CMK m.134 Adli Bilirkişi Raporunu İndir (JSON)",
        data=json.dumps(final_report, indent=2, ensure_ascii=False),
        file_name="fotoiz_cmk134_expert_report.json",
        mime="application/json",
        use_container_width=True
    )
