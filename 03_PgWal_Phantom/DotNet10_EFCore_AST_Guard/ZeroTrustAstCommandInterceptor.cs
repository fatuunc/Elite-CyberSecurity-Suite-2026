using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace PgWalPhantom.Security;

public sealed partial class ZeroTrustAstCommandInterceptor : DbCommandInterceptor
{
    private readonly HashSet<string> _trustedStructuralHashes;
    public ZeroTrustAstCommandInterceptor(IEnumerable<string> baselineHashes)
        => _trustedStructuralHashes = new HashSet<string>(baselineHashes, StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(@"('[^']*')|(\b\d+\b)|(@\w+|\$\d+)", RegexOptions.Compiled)]
    private static partial Regex LiteralNormalizerRegex();

    public static string ComputeStructuralAstHash(string sqlCommandText)
    {
        string skeleton = LiteralNormalizerRegex().Replace(sqlCommandText ?? "", "?");
        skeleton = Regex.Replace(skeleton, @"\s+", " ").Trim().ToUpperInvariant();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(skeleton)));
    }

    public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
    {
        string currentHash = ComputeStructuralAstHash(command.CommandText);
        if (!_trustedStructuralHashes.Contains(currentHash))
            throw new SecurityException($"[PgWal-Phantom ZERO-TRUST AST BLOCK] Unauthorized SQL AST Hash: {currentHash}");
        return base.ReaderExecuting(command, eventData, result);
    }
}
