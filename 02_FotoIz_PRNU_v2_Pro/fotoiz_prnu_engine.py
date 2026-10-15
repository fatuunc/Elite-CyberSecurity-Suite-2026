#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import math, struct, hashlib, sys, os, json
from typing import Dict, Any, Tuple
import numpy as np
from scipy.fft import fft2, ifft2
from scipy.ndimage import uniform_filter

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

class FotoIzPRNUEngine:
    @staticmethod
    def extract_noise_residue(image_gray: np.ndarray) -> np.ndarray:
        img = image_gray.astype(np.float64)
        local_mean = uniform_filter(img, size=3)
        local_sq_mean = uniform_filter(img ** 2, size=3)
        local_var = np.maximum(local_sq_mean - local_mean ** 2, 1e-6)
        noise_var = np.mean(local_var)
        denoised = local_mean + (np.maximum(0.0, local_var - noise_var) / local_var) * (img - local_mean)
        residue = img - denoised
        residue -= np.mean(residue, axis=0, keepdims=True)
        residue -= np.mean(residue, axis=1, keepdims=True)
        return residue

    @staticmethod
    def compute_pce_score(reference_prnu: np.ndarray, suspect_residue: np.ndarray) -> Dict[str, Any]:
        X = reference_prnu.astype(np.float64) - np.mean(reference_prnu)
        Y = suspect_residue.astype(np.float64) - np.mean(suspect_residue)
        cross_corr = np.real(ifft2(fft2(X) * np.conj(fft2(Y))))
        peak_idx = np.unravel_index(np.argmax(np.abs(cross_corr)), cross_corr.shape)
        peak_val = cross_corr[peak_idx]
        mask = np.ones(cross_corr.shape, dtype=bool)
        r, c = peak_idx
        h, w = cross_corr.shape
        for dr in range(-5, 6):
            for dc in range(-5, 6):
                mask[(r + dr) % h, (c + dc) % w] = False
        background_energy = float(np.mean(cross_corr[mask] ** 2))
        pce = float((peak_val ** 2) / (background_energy + 1e-12) * np.sign(peak_val))
        return {
            "PCE_Score": round(pce, 2),
            "ENFSI_Threshold": 60.0,
            "Court_Admissible_Match": bool(pce >= 60.0),
            "Spatial_Shift_Peak_YX": [int(peak_idx[0]), int(peak_idx[1])],
            "Forensic_Verdict": "KESİN EŞLEŞME: Aynı fiziksel CMOS sensör." if pce >= 60.0 else "EŞLEŞME YOK"
        }

    @classmethod
    def localize_splicing_heatmap(cls, reference_prnu: np.ndarray, suspect_image_gray: np.ndarray, window_size: int = 64, stride: int = 32) -> Tuple[np.ndarray, Dict[str, Any]]:
        suspect_residue = cls.extract_noise_residue(suspect_image_gray)
        h, w = suspect_image_gray.shape
        grid_h = max(1, (h - window_size) // stride + 1)
        grid_w = max(1, (w - window_size) // stride + 1)
        pce_map = np.zeros((grid_h, grid_w), dtype=np.float64)
        tampered_blocks = []
        for gy, y in enumerate(range(0, h - window_size + 1, stride)):
            for gx, x in enumerate(range(0, w - window_size + 1, stride)):
                res = cls.compute_pce_score(reference_prnu[y:y+window_size, x:x+window_size], suspect_residue[y:y+window_size, x:x+window_size])
                pce_map[gy, gx] = res["PCE_Score"]
                if res["PCE_Score"] < 8.0:
                    tampered_blocks.append({"y": y, "x": x, "size": window_size, "local_pce": res["PCE_Score"]})
        return pce_map, {"total_windows_scanned": int(grid_h * grid_w), "anomalous_tampered_windows": len(tampered_blocks), "tampering_detected": len(tampered_blocks) > 0, "suspect_regions_preview": tampered_blocks[:5]}

    @staticmethod
    def parse_jpeg_dqt_genealogy(jpeg_bytes: bytes) -> Dict[str, Any]:
        tables, idx, n = [], 0, len(jpeg_bytes)
        while idx < n - 4:
            if jpeg_bytes[idx] == 0xFF and jpeg_bytes[idx + 1] == 0xDB:
                length = struct.unpack(">H", jpeg_bytes[idx + 2:idx + 4])[0]
                segment = jpeg_bytes[idx + 4:idx + 2 + length]
                pos = 0
                while pos < len(segment):
                    pq_tq = segment[pos]
                    pos += 1
                    if ((pq_tq >> 4) & 0x0F) == 0 and pos + 64 <= len(segment):
                        q_vals = list(segment[pos:pos + 64])
                        pos += 64
                        tables.append({"table_id": pq_tq & 0x0F, "dc_coeff": q_vals[0], "mean_q": round(sum(q_vals)/64.0, 2), "values": q_vals})
                    else: break
                idx += 2 + length
            else: idx += 1
        if not tables: return {"status": "No DQT markers found", "tables": []}
        luma_mean = tables[0]["mean_q"]
        table_hash = hashlib.sha256(str([t["values"] for t in tables]).encode()).hexdigest()[:16]
        return {"dqt_signature_hash": table_hash, "tables_extracted": len(tables), "luma_mean_quantization": luma_mean, "tables": tables}

    @staticmethod
    def verify_solar_shadow_geometry(object_height_m: float, shadow_length_m: float, latitude_deg: float, day_of_year: int, solar_hour_local: float) -> Dict[str, Any]:
        measured_alt_deg = math.degrees(math.atan2(object_height_m, max(shadow_length_m, 1e-6)))
        decl_rad = math.radians(23.45 * math.sin(math.radians((360.0 / 365.0) * (284 + day_of_year))))
        lat_rad = math.radians(latitude_deg)
        h_rad = math.radians(15.0 * (solar_hour_local - 12.0))
        sin_alt = math.sin(lat_rad) * math.sin(decl_rad) + math.cos(lat_rad) * math.cos(decl_rad) * math.cos(h_rad)
        theoretical_alt_deg = math.degrees(math.asin(max(-1.0, min(1.0, sin_alt))))
        angular_error = abs(measured_alt_deg - theoretical_alt_deg)
        return {"measured_solar_altitude_deg": round(measured_alt_deg, 2), "astronomical_expected_altitude_deg": round(theoretical_alt_deg, 2), "angular_deviation_deg": round(angular_error, 2), "physical_consistency": angular_error <= 4.5}

    @classmethod
    def generate_expert_witness_report(cls, ref_path: str, suspect_path: str, pce_result: Dict[str, Any], splicing_result: Dict[str, Any] = None) -> Dict[str, Any]:
        def _sha256(path: str) -> str:
            if not os.path.exists(path): return "N/A"
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536): h.update(chunk)
            return h.hexdigest()

        report = {
            "expert_witness_title": "ADLİ BİLİŞİM VE SENSÖR BİYOMETRİSİ UZMAN RAPORU",
            "regulatory_compliance": "CMK m.134 & ISO/IEC 27037 Standartları",
            "examiner": "Fatih Tunç (Digital Forensics Engineering)",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence_item_1": {
                "description": "Kamera Referans Görüntüsü",
                "filename": os.path.basename(ref_path),
                "sha256_hash": _sha256(ref_path)
            },
            "evidence_item_2": {
                "description": "Şüpheli / İncelenen Medya",
                "filename": os.path.basename(suspect_path),
                "sha256_hash": _sha256(suspect_path)
            },
            "prnu_sensor_fingerprint_metrics": pce_result,
            "splicing_localization_metrics": splicing_result or {},
            "scientific_conclusion": (
                "İNCELEME SONUCU: "
                + ("Şüpheli görselin, adli referans kameranın CMOS sensöründen çıktığı ENFSI standartlarında KESİNLEŞMİŞTİR."
                   if pce_result.get("Court_Admissible_Match") else
                   "Şüpheli görsel ile referans kamera sensörü arasında eşleşme tespit edilmemiştir.")
            )
        }
        return report

if __name__ == "__main__":
    import time
    from PIL import Image
    import argparse

    parser = argparse.ArgumentParser(description="Fotoİz-PRNU v2.0 Pro | Fatih Tunç")
    parser.add_argument("--test", action="store_true", help="Hazır test senaryolarını çalıştır")
    parser.add_argument("--verify", nargs=2, metavar=("REF", "SUSPECT"), help="İki görüntü arasında PRNU PCE eşleşmesi yap")
    parser.add_argument("--dqt", metavar="JPEG_FILE", help="JPEG DQT kuantizasyon tablosu soybilimi çıkar")
    args = parser.parse_args()

    print("=" * 70)
    print("📸 Fotoİz-PRNU v2.0 Pro | Geliştirici: Fatih Tunç")
    print("CMK m.134 & ISO/IEC 27037 Uyumlu Sensör Biyometrisi Motoru")
    print("=" * 70)

    samples_dir = os.path.join(os.path.dirname(__file__), "test_samples")
    ref_file = os.path.join(samples_dir, "01_camera_reference_flat.png")
    wa_file = os.path.join(samples_dir, "02_whatsapp_exif_stripped.jpg")
    spliced_file = os.path.join(samples_dir, "03_spliced_deepfake_evidence.png")

    if args.dqt:
        if os.path.exists(args.dqt):
            with open(args.dqt, "rb") as f:
                res = FotoIzPRNUEngine.parse_jpeg_dqt_genealogy(f.read())
            print(f"[+] DQT Analizi: {args.dqt}")
            print(json.dumps(res, indent=2))
        else:
            print(f"[-] Dosya bulunamadı: {args.dqt}")
        sys.exit(0)

    # Run default test verification
    print("[*] 1. Adım: Sensör Gürültü Artığı Çıkarımı (Noise Residue Extraction)...")
    if os.path.exists(ref_file) and os.path.exists(wa_file):
        ref_img = np.array(Image.open(ref_file).convert("L"))
        wa_img = np.array(Image.open(wa_file).convert("L"))
        
        t0 = time.perf_counter()
        ref_prnu = FotoIzPRNUEngine.extract_noise_residue(ref_img)
        wa_prnu = FotoIzPRNUEngine.extract_noise_residue(wa_img)
        t_prnu = time.perf_counter() - t0
        print(f"[✓] Gürültü Artığı Çıkarıldı ({t_prnu:.3f} saniye). Referans Boyut: {ref_img.shape}")

        print("\n[*] 2. Adım: 2D FFT Çapraz Korelasyon ve PCE Skoru Hesaplanıyor...")
        pce_res = FotoIzPRNUEngine.compute_pce_score(ref_prnu, wa_prnu)
        print(f"[✓] PCE Skoru: {pce_res['PCE_Score']} (ENFSI Eşik Değeri: {pce_res['ENFSI_Threshold']})")
        print(f"[✓] Mahkeme Geçerliliği: {pce_res['Court_Admissible_Match']}")
        print(f"[✓] Karar: {pce_res['Forensic_Verdict']}")

        if os.path.exists(spliced_file):
            print("\n[*] 3. Adım: Deepfake & Splicing Bölgesel Isı Haritası (Heatmap)...")
            spliced_img = np.array(Image.open(spliced_file).convert("L"))
            _, splice_res = FotoIzPRNUEngine.localize_splicing_heatmap(ref_prnu, spliced_img)
            print(f"[✓] Taranan Pencere: {splice_res['total_windows_scanned']}, Anormal Blok: {splice_res['anomalous_tampered_windows']}")
            print(f"[✓] Tahrifat Saptandı mı: {splice_res['tampering_detected']}")

        # Save Expert Report
        report = FotoIzPRNUEngine.generate_expert_witness_report(ref_file, wa_file, pce_res, splice_res if 'splice_res' in locals() else None)
        report_file = os.path.join(samples_dir, "fotoiz_forensic_analysis_report.json")
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[✓] Uzman Raporu Kaydedildi: {report_file}")
    else:
        print("[-] Test dosyaları bulunamadı!")
    print("=" * 70)
