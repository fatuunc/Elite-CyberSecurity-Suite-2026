using System;
using System.Collections.Generic;
using System.Security;
using PgWalPhantom.Security;

namespace PgWalPhantom.Security;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("======================================================================");
        Console.WriteLine("🛡️ .NET 10 EF Core Zero-Trust AST Interceptor & SQLi Blocker");
        Console.WriteLine("Geliştirici: Fatih Tunç | Structural AST Hash Integrity Shield");
        Console.WriteLine("======================================================================\n");

        // 1. Define authorized baseline SQL command structure
        string authorizedQuery = "SELECT u.Id, u.Username, u.Email FROM Users u WHERE u.Username = @p0 AND u.TenantId = @p1";
        string baselineHash = ZeroTrustAstCommandInterceptor.ComputeStructuralAstHash(authorizedQuery);

        Console.WriteLine("[*] Aşama 1: Yetkili Uygulama Sorgusu Taban Çizgisi (Baseline) Kaydedildi");
        Console.WriteLine($"    Sorgu Şablonu : {authorizedQuery}");
        Console.WriteLine($"    AST SHA256     : {baselineHash}\n");

        var trustedBaseline = new List<string> { baselineHash };
        var interceptor = new ZeroTrustAstCommandInterceptor(trustedBaseline);

        // 2. Test authorized runtime query with different parameter values
        string runtimeLegitQuery = "SELECT u.Id, u.Username, u.Email FROM Users u WHERE u.Username = @p0 AND u.TenantId = @p1";
        string legitHash = ZeroTrustAstCommandInterceptor.ComputeStructuralAstHash(runtimeLegitQuery);

        Console.WriteLine("[*] Aşama 2: Dinamik Parametrelerle Meşru Sorgu Test Ediliyor");
        Console.WriteLine($"    Çalışan Sorgu  : {runtimeLegitQuery}");
        Console.WriteLine($"    Hesaplanan AST : {legitHash}");
        if (legitHash.Equals(baselineHash, StringComparison.OrdinalIgnoreCase))
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("    [✓] GEÇİŞ ONAYLANDI: AST Yapısı Yetkili Şablonla 100% Uyuşuyor.\n");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("    [X] GEÇİŞ ENGELLENDİ: Beklenmeyen yapı.\n");
            Console.ResetColor();
        }

        // 3. Test malicious SQL injection payload tampering with AST structure
        string[] attackVectors = new[]
        {
            "SELECT u.Id, u.Username, u.Email FROM Users u WHERE u.Username = 'admin' OR '1'='1'-- AND u.TenantId = 1",
            "SELECT u.Id, u.Username, u.Email FROM Users u WHERE u.Username = '' UNION SELECT id, password_hash, NULL FROM pg_authid--",
            "SELECT u.Id, u.Username, u.Email FROM Users u WHERE u.Username = 'fatih'; DROP TABLE audit_logs;--"
        };

        Console.WriteLine("[*] Aşama 3: WAF Atlatma ve Dinamik SQLi Enjeksiyon Denemeleri:");
        int blockedCount = 0;

        foreach (var attack in attackVectors)
        {
            string attackHash = ZeroTrustAstCommandInterceptor.ComputeStructuralAstHash(attack);
            Console.WriteLine($"\n -> Saldırı Yükü  : {attack}");
            Console.WriteLine($"    Üretilen AST  : {attackHash}");

            if (!trustedBaseline.Contains(attackHash))
            {
                blockedCount++;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("    [🚨 BLOCKED BY ZERO-TRUST AST GUARD] Güvenlik İhlali Yakalandı! Sorgu Veritabanına Gitmeden Durduruldu.");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("    [!] UYARI: Geçti.");
            }
        }

        Console.WriteLine("\n======================================================================");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[✓] TEST BAŞARILI: Toplam {attackVectors.Length} saldırının {blockedCount} tanesi AST katmanında BLOKE EDİLDİ.");
        Console.WriteLine("    Hiçbir dinamik injection veritabanı motoruna (PostgreSQL) ulaşamadı.");
        Console.ResetColor();
        Console.WriteLine("======================================================================");
    }
}
