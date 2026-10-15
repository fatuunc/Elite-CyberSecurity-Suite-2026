#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, struct, sys, os, csv
from typing import List, Dict, Any

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

PAGE_SIZE = 8192
HEAP_XMAX_INVALID = 0x0800

class PgWalPhantomCarver:
    @staticmethod
    def carve_heap_file(filepath: str) -> Dict[str, Any]:
        live_tuples, dead_deleted_tuples = [], []
        with open(filepath, "rb") as f:
            page_num = 0
            while True:
                page_bytes = f.read(PAGE_SIZE)
                if len(page_bytes) < PAGE_SIZE: break
                pd_lsn, pd_checksum, pd_flags, pd_lower, pd_upper, pd_special, pd_pagesize_ver, pd_prune_xid = struct.unpack("<QHHHHHHI", page_bytes[:24])
                num_line_pointers = max(0, (pd_lower - 24) // 4)
                for lp_idx in range(num_line_pointers):
                    lp_offset = 24 + (lp_idx * 4)
                    (lp_raw,) = struct.unpack("<I", page_bytes[lp_offset:lp_offset + 4])
                    tuple_offset = lp_raw & 0x7FFF
                    lp_flags = (lp_raw >> 15) & 0x03
                    tuple_len = (lp_raw >> 17) & 0x7FFF
                    if lp_flags != 1 or tuple_len < 23 or (tuple_offset + tuple_len > PAGE_SIZE): continue
                    tuple_data = page_bytes[tuple_offset:tuple_offset + tuple_len]
                    t_xmin, t_xmax, t_cid, bi_hi, bi_lo, ip_posid, t_infomask2, t_infomask, t_hoff = struct.unpack("<IIIHHHHHB", tuple_data[:23])
                    is_deleted = (t_xmax != 0) and not (t_infomask & HEAP_XMAX_INVALID)
                    raw_payload = tuple_data[t_hoff:]
                    ascii_carved = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_payload)
                    record = {
                        "page_number": page_num, "item_pointer_index": lp_idx + 1, "ctid": f"({page_num},{lp_idx + 1})",
                        "tuple_byte_offset": tuple_offset, "tuple_length_bytes": tuple_len,
                        "t_xmin_created_xid": t_xmin, "t_xmax_deleted_xid": t_xmax,
                        "column_count_natts": t_infomask2 & 0x07FF,
                        "status": "DELETED_DEAD_TUPLE" if is_deleted else "LIVE_ACTIVE_TUPLE",
                        "raw_payload_hex": raw_payload.hex(), "carved_utf8_preview": ascii_carved
                    }
                    (dead_deleted_tuples if is_deleted else live_tuples).append(record)
                page_num += 1
        return {
            "forensic_tool": "PgWal-Phantom v1.0 Binary Heap Carver", "author": "Fatih Tunç",
            "inspected_file": filepath, "total_8kb_pages_scanned": page_num,
            "active_live_tuples_count": len(live_tuples),
            "recovered_deleted_tuples_count": len(dead_deleted_tuples),
            "recovered_deleted_records": dead_deleted_tuples, "active_records": live_tuples
        }

def build_synthetic_postgres_heap_file(output_path: str) -> None:
    sample_tuples = [
        (1041, 0,    4, False, "LOG-001|2026-10-15T08:00:00Z|INFO|System startup normal - KMBB Gateway"),
        (1042, 1089, 4, True,  "LOG-002|2026-10-15T08:12:44Z|CRITICAL|Unauthorized SSH root login from 185.220.101.42"),
        (1043, 1089, 4, True,  "LOG-003|2026-10-15T08:13:02Z|ALERT|WAF Rule 942100 SQLi Bypass attempt by user=admin_shadow"),
        (1044, 1090, 4, True,  "LOG-004|2026-10-15T08:14:19Z|CRITICAL|Exfiltration of /etc/shadow & pg_authid table dump"),
        (1045, 0,    4, False, "LOG-005|2026-10-15T08:15:00Z|INFO|Routine health check OK")
    ]
    page_buf = bytearray(PAGE_SIZE)
    current_upper = PAGE_SIZE
    line_pointers = []
    for idx, (xmin, xmax, natts, is_del, text_data) in enumerate(sample_tuples, start=1):
        payload_bytes = text_data.encode("utf-8")
        t_infomask = 0x0902 if not is_del else 0x0102
        tuple_header = struct.pack("<IIIHHHHHBx", xmin, xmax, 0, 0, 0, idx, natts & 0x07FF, t_infomask, 24)
        full_tuple = tuple_header + payload_bytes
        t_len = len(full_tuple)
        current_upper = (current_upper - t_len) & ~0x03
        page_buf[current_upper:current_upper + t_len] = full_tuple
        line_pointers.append((current_upper & 0x7FFF) | (1 << 15) | ((t_len & 0x7FFF) << 17))
    pd_lower = 24 + len(line_pointers) * 4
    page_buf[:24] = struct.pack("<QHHHHHHI", 0x000000010000A4F0, 0x4654, 0, pd_lower, current_upper, PAGE_SIZE, (PAGE_SIZE | 4), 1089)
    for i, lp_val in enumerate(line_pointers):
        page_buf[24 + i * 4:28 + i * 4] = struct.pack("<I", lp_val)
    with open(output_path, "wb") as f:
        f.write(page_buf)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PgWal-Phantom v1.0 | PostgreSQL Binary Heap Carver (Fatih Tunç)")
    parser.add_argument("--heap", metavar="FILE", help="İncelenecek PostgreSQL 8KB Heap dosya yolu")
    parser.add_argument("--generate", metavar="FILE", help="Sentetik PostgreSQL adli heap dosyası üret")
    args = parser.parse_args()

    print("=" * 70)
    print("🐘 PgWal-Phantom v1.0 | PostgreSQL Binary Heap Carver")
    print("Geliştirici: Fatih Tunç | MVCC Dead Tuple Adli Kurtarma Motoru")
    print("=" * 70)

    samples_dir = os.path.join(os.path.dirname(__file__), "forensic_samples")
    default_heap = os.path.join(samples_dir, "pg_heap_relfilenode_16384.bin")

    target_file = args.heap if args.heap else default_heap

    if args.generate:
        print(f"[*] Sentetik PostgreSQL Heap üretiliyor: {args.generate}")
        build_synthetic_postgres_heap_file(args.generate)
        print("[✓] Sentetik dosya başarıyla oluşturuldu.")
        sys.exit(0)

    if not os.path.exists(target_file):
        print(f"[*] Varsayılan heap bulunamadı, otomatik sentetik oluşturuluyor: {target_file}")
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        build_synthetic_postgres_heap_file(target_file)

    print(f"[*] Analiz Başlatılıyor: {target_file}")
    res = PgWalPhantomCarver.carve_heap_file(target_file)
    print(f"[✓] Taranan 8KB Sayfa Sayısı : {res['total_8kb_pages_scanned']}")
    print(f"[✓] Aktif Canlı Kayıtlar    : {res['active_live_tuples_count']}")
    print(f"[✓] Kurtarılan Silinmiş Kayıt: {res['recovered_deleted_tuples_count']}")

    print("\n🚨 KURTARILAN SİLİNMİŞ (DEAD TUPLE) KAYITLAR (Saldırgan İzleri):")
    for r in res["recovered_deleted_records"]:
        print(f" -> CTID: {r['ctid']} | xmin: {r['t_xmin_created_xid']} | xmax (Deleted XID): {r['t_xmax_deleted_xid']}")
        print(f"    Payload: {r['carved_utf8_preview']}")

    # Export report
    report_file = os.path.join(samples_dir, "carved_dead_tuples_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print(f"\n[✓] Adli Rapor Kaydedildi: {report_file}")
    print("=" * 70)
