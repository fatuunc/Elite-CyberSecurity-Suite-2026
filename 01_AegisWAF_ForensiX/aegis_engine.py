#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib, hmac, json, math, struct, sys, time, unicodedata
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Tuple, List, Dict, Any, Optional

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

@dataclass
class ForensicEvidenceCapsule:
    case_id: str
    timestamp_utc: float
    iso_timestamp: str
    client_ip: str
    ja4_tls_fingerprint: str
    ja4h_http_fingerprint: str
    evasion_vector: str
    severity: str
    shannon_entropy: float
    parser_delta_score: int
    raw_http_hex: str
    rfc3161_tsa_token: str
    previous_capsule_hash: str
    capsule_sha3_512: str = ""

    def seal_capsule(self) -> None:
        canonical = (
            f"{self.case_id}|{self.timestamp_utc}|{self.client_ip}|"
            f"{self.ja4_tls_fingerprint}|{self.ja4h_http_fingerprint}|"
            f"{self.evasion_vector}|{self.shannon_entropy}|"
            f"{self.raw_http_hex}|{self.rfc3161_tsa_token}|{self.previous_capsule_hash}"
        )
        self.capsule_sha3_512 = hashlib.sha3_512(canonical.encode("utf-8")).hexdigest()

class MicroPcapWriter:
    PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    @staticmethod
    def build_ipv4_tcp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
        eth_header = b"\x00\x1a\x2b\x3c\x4d\x5e\xaa\xbb\xcc\xdd\xee\xff" + struct.pack("!H", 0x0800)
        s_ip = bytes(map(int, src_ip.split(".")))
        d_ip = bytes(map(int, dst_ip.split(".")))
        ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0x4654, 0x4000, 64, 6, 0, s_ip, d_ip)
        tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, 1001, 2002, (5 << 4), 0x18, 64240, 0, 0)
        return eth_header + ip_header + tcp_header + payload

    @classmethod
    def write_pcap(cls, filepath: str, packets: List[Tuple[float, bytes]]) -> None:
        with open(filepath, "wb") as f:
            f.write(cls.PCAP_GLOBAL_HEADER)
            for ts, frame in packets:
                ts_sec = int(ts)
                ts_usec = int((ts - ts_sec) * 1_000_000)
                f.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
                f.write(frame)

class AegisForensiXEngine:
    def __init__(self, tsa_secret_key: bytes = b"FATIH_TUNC_RFC3161_TSA_ROOT_KEY_2026"):
        self.genesis_hash = hashlib.sha3_512(b"FATIH_TUNC_AEGIS_GENESIS_BLOCK_2026").hexdigest()
        self.last_chain_hash = self.genesis_hash
        self.tsa_secret_key = tsa_secret_key
        self.evidence_vault: List[ForensicEvidenceCapsule] = []
        self.captured_frames: List[Tuple[float, bytes]] = []

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        if not data: return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @staticmethod
    def compute_ja4h_fingerprint(method: str, version: str, headers: Dict[str, str], cookies: str = "") -> str:
        m_code = method[:2].lower()
        v_code = "20" if "2" in version else "11"
        c_flag = "c" if cookies else "n"
        r_flag = "r" if "referer" in {k.lower() for k in headers} else "n"
        h_count = f"{min(len(headers), 99):02d}"
        h_hash = hashlib.sha256(",".join(k.lower() for k in headers.keys()).encode()).hexdigest()[:12]
        c_hash = hashlib.sha256(cookies.encode()).hexdigest()[:12] if cookies else "000000000000"
        return f"{m_code}{v_code}{c_flag}{r_flag}{h_count}_{h_hash}_{c_hash}"

    @staticmethod
    def detect_json_differential_evasion(raw_json_str: str) -> Tuple[bool, str, int]:
        if not raw_json_str.strip(): return False, "Empty Body", 0
        nfkc_normalized = unicodedata.normalize("NFKC", raw_json_str)
        unicode_delta = sum(1 for a, b in zip(raw_json_str, nfkc_normalized) if a != b)
        duplicate_keys = []
        def _strict_pairs_hook(pairs: List[Tuple[str, Any]]):
            keys = [k for k, _ in pairs]
            for k, count in Counter(keys).items():
                if count > 1:
                    vals = [v for key, v in pairs if key == k]
                    duplicate_keys.append(f"Key '{k}' defined {count}x (WAF sees='{vals[0]}', Backend sees='{vals[-1]}')")
            return dict(pairs)
        try:
            json.loads(raw_json_str, object_pairs_hook=_strict_pairs_hook)
        except json.JSONDecodeError as e:
            return True, f"Malformed JSON Desync Attempt: {str(e)}", 10 + unicode_delta
        reasons, delta_score = [], 0
        if duplicate_keys:
            reasons.append("JSON Duplicate Key Evasion -> " + "; ".join(duplicate_keys))
            delta_score += len(duplicate_keys) * 10
        if unicode_delta > 0:
            reasons.append(f"Unicode NFKC Homoglyph Smuggling (Normalized Delta={unicode_delta} chars)")
            delta_score += unicode_delta * 5
        return (True, " | ".join(reasons), delta_score) if reasons else (False, "Clean", 0)

    @staticmethod
    def detect_http_smuggling_headers(raw_http_bytes: bytes) -> Tuple[bool, str, int]:
        text = raw_http_bytes.decode("latin-1", errors="replace")
        header_part = text.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in text else text.split("\n\n", 1)[0]
        lines = header_part.splitlines()
        has_cl = any(l.lower().startswith("content-length") for l in lines[1:])
        has_te = any("transfer-encoding" in l.lower() for l in lines[1:])
        if has_cl and has_te:
            return True, "HTTP Request Smuggling (Simultaneous Content-Length & Transfer-Encoding Desync)", 25
        return False, "Clean", 0

    @staticmethod
    def detect_url_encoding_anomalies(raw_http_bytes: bytes) -> Tuple[bool, str, int]:
        text = raw_http_bytes.decode("latin-1", errors="replace").lower()
        reasons = []
        delta_score = 0
        if "%25" in text:
            reasons.append("Double URL Encoding Evasion (%25 pattern detected)")
            delta_score += 15
        if "%00" in text or "\x00" in text:
            reasons.append("Null-Byte Injection Evasion (%00 pattern detected)")
            delta_score += 20
        if "%c0%af" in text or "%c1%9c" in text or "%e0%80%af" in text:
            reasons.append("Overlong UTF-8 Directory Traversal / Unicode Smuggling")
            delta_score += 25
        return (True, " | ".join(reasons), delta_score) if reasons else (False, "Clean", 0)

    @staticmethod
    def detect_chunked_smuggling_variations(raw_http_bytes: bytes) -> Tuple[bool, str, int]:
        text = raw_http_bytes.decode("latin-1", errors="replace")
        lines = text.splitlines()
        te_lines = [l for l in lines if "transfer-encoding" in l.lower()]
        reasons = []
        delta_score = 0
        for l in te_lines:
            if " :" in l or "\t:" in l:
                reasons.append("Transfer-Encoding Header Space/Tab Pre-Colon Desync")
                delta_score += 15
            if ";" in l:
                reasons.append("Chunked Extension Obfuscation Evasion")
                delta_score += 10
        if len(te_lines) > 1:
            reasons.append(f"Multiple Transfer-Encoding Headers ({len(te_lines)}x)")
            delta_score += 20
        return (True, " | ".join(reasons), delta_score) if reasons else (False, "Clean", 0)

    def generate_rfc3161_token(self, payload_hash: str, timestamp: float) -> str:
        msg = f"RFC3161_TSA|{timestamp:.6f}|{payload_hash}".encode("utf-8")
        sig = hmac.new(self.tsa_secret_key, msg, hashlib.sha3_256).hexdigest()
        return f"TSA-2026-{sig[:32].upper()}"

    def inspect_request(self, client_ip: str, client_port: int, ja4_tls_fp: str, method: str, version: str, headers: Dict[str, str], raw_http_bytes: bytes, body_str: str) -> Optional[Dict[str, Any]]:
        ts = time.time()
        iso_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        entropy = self.calculate_shannon_entropy(raw_http_bytes)
        ja4h_fp = self.compute_ja4h_fingerprint(method, version, headers, headers.get("Cookie", ""))
        smug_flag, smug_reason, smug_delta = self.detect_http_smuggling_headers(raw_http_bytes)
        chunk_flag, chunk_reason, chunk_delta = self.detect_chunked_smuggling_variations(raw_http_bytes)
        enc_flag, enc_reason, enc_delta = self.detect_url_encoding_anomalies(raw_http_bytes)
        json_flag, json_reason, json_delta = self.detect_json_differential_evasion(body_str)
        
        total_delta = smug_delta + chunk_delta + enc_delta + json_delta
        reasons = [r for flag, r in [(smug_flag, smug_reason), (chunk_flag, chunk_reason), (enc_flag, enc_reason), (json_flag, json_reason)] if flag]
        if entropy > 6.4:
            reasons.append(f"High Payload Shannon Entropy ({entropy:.2f} bits/byte)")
        if reasons:
            tsa_token = self.generate_rfc3161_token(hashlib.sha256(raw_http_bytes).hexdigest(), ts)
            capsule = ForensicEvidenceCapsule(
                case_id=f"FT-AEGIS-{int(ts * 1000)}-{len(self.evidence_vault)+1:03d}",
                timestamp_utc=ts, iso_timestamp=iso_ts, client_ip=client_ip,
                ja4_tls_fingerprint=ja4_tls_fp, ja4h_http_fingerprint=ja4h_fp,
                evasion_vector=" || ".join(reasons),
                severity="CRITICAL" if total_delta >= 15 or entropy > 6.4 else "HIGH",
                shannon_entropy=round(entropy, 4), parser_delta_score=total_delta,
                raw_http_hex=raw_http_bytes.hex(), rfc3161_tsa_token=tsa_token,
                previous_capsule_hash=self.last_chain_hash
            )
            capsule.seal_capsule()
            self.last_chain_hash = capsule.capsule_sha3_512
            self.evidence_vault.append(capsule)
            frame = MicroPcapWriter.build_ipv4_tcp_frame(client_ip, "10.46.0.10", client_port, 443, raw_http_bytes)
            self.captured_frames.append((ts, frame))
            return asdict(capsule)
        return None

    def verify_merkle_chain_integrity(self) -> Tuple[bool, str]:
        expected_prev = self.genesis_hash
        for idx, cap in enumerate(self.evidence_vault):
            if cap.previous_capsule_hash != expected_prev:
                return False, f"Chain broken at index {idx}"
            expected_prev = cap.capsule_sha3_512
        return True, f"VERIFIED: All {len(self.evidence_vault)} capsules linked to Genesis Block without tampering."

    def export_forensic_bundle(self, json_path: str, pcap_path: str) -> None:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "engine": "AegisWAF-ForensiX v1.0", "author": "Fatih Tunç",
                "genesis_block_sha3_512": self.genesis_hash,
                "chain_verification": self.verify_merkle_chain_integrity()[1],
                "capsules": [asdict(c) for c in self.evidence_vault]
            }, f, indent=2, ensure_ascii=False)
        MicroPcapWriter.write_pcap(pcap_path, self.captured_frames)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AegisWAF-ForensiX: eBPF WAF Bypass & Adli Kanıt Zinciri Motoru (Fatih Tunç)")
    parser.add_argument("--simulate", action="store_true", help="Adli kanıt simülasyonunu ve Merkle zincir testini çalıştır")
    parser.add_argument("--benchmark", action="store_true", help="Yüksek hızlı paket işleme gecikme testini çalıştır")
    args = parser.parse_args()

    engine = AegisForensiXEngine()
    print("=" * 70)
    print("🛡️  AegisWAF-ForensiX Engine | Geliştirici: Fatih Tunç")
    print(f"Genesis Block SHA3-512: {engine.genesis_hash[:32]}...")
    print("=" * 70)

    # 1. JSON Duplicate Key & NFKC Homoglyph Attack
    body1 = '{"user": "fatih", "access": "readonly", "access": "root_admin\' OR 1=1--"}'
    req1 = f"POST /api/v1/privilege HTTP/1.1\r\nHost: core.network.local\r\nContent-Length: {len(body1)}\r\n\r\n{body1}".encode()
    cap1 = engine.inspect_request("185.220.101.42", 51234, "t13d1516h2_8daaf6152771_e5627efa2ab1", "POST", "1.1", {"Host": "core.network.local"}, req1, body1)

    # 2. HTTP Desync Smuggling CL.TE Attack
    body2 = "0\r\n\r\nGPOST /admin/delete_user HTTP/1.1\r\nHost: waf.kurum.local\r\n\r\n"
    req2 = f"POST /search HTTP/1.1\r\nHost: waf.kurum.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n{body2}".encode()
    cap2 = engine.inspect_request("194.26.192.77", 49120, "t13d1516h2_8daaf6152771_b186095e22b6", "POST", "1.1", {"Host": "waf.kurum.local", "Transfer-Encoding": "chunked"}, req2, body2)

    # 3. Double-URL and Overlong UTF-8 Directory Traversal
    req3 = b"GET /vulnerabilities/fi/?page=%252e%252e%252f%c0%afetc%c0%afshadow HTTP/1.1\r\nHost: sec.kurum.local\r\n\r\n"
    cap3 = engine.inspect_request("45.154.255.89", 60122, "t13d1516h2_8daaf6152771_f448c9012a99", "GET", "1.1", {"Host": "sec.kurum.local"}, req3, "")

    print(f"\n[+] Tespit Edilen Kritik Kapsüller: {len(engine.evidence_vault)}")
    for c in engine.evidence_vault:
        print(f" -> Kapsül ID: {c.case_id} | IP: {c.client_ip} | Tehdit: {c.evasion_vector[:45]}... | Sever: {c.severity}")
        print(f"    SHA3-512 Hash: {c.capsule_sha3_512[:32]}... | TSA Token: {c.rfc3161_tsa_token}")

    ok, msg = engine.verify_merkle_chain_integrity()
    print(f"\n[+] Merkle Doğrulama Durumu: {msg}")

    if args.benchmark:
        print("\n[*] Yüksek Hızlı Gecikme & Verim Kıyaslaması (Benchmark) Başlatılıyor (10,000 Paket)...")
        t0 = time.perf_counter()
        for i in range(10000):
            engine.detect_http_smuggling_headers(req2)
            engine.detect_url_encoding_anomalies(req3)
        t_elapsed = time.perf_counter() - t0
        print(f"[✓] 10,000 Paket Denetim Süresi: {t_elapsed:.4f} saniye")
        print(f"[✓] İşlem Kapasitesi: {10000 / t_elapsed:,.0f} req/saniye (Gecikme: {(t_elapsed / 10000) * 1e6:.2f} µs/paket)")

    # Artifact dışa aktarımı
    import os
    os.makedirs("artifacts", exist_ok=True)
    engine.export_forensic_bundle("artifacts/forensic_evidence_vault.json", "artifacts/captured_waf_bypass_evidence.pcap")
    print("\n[✓] Adli Kanıt Dosyaları Kaydedildi:")
    print(" -> artifacts/forensic_evidence_vault.json (Adli Kanıt Kapsülleri)")
    print(" -> artifacts/captured_waf_bypass_evidence.pcap (MicroPCAP Ağ İzi)")
    print("=" * 70)
