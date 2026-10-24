using System.Security.Cryptography;

namespace RepoCuck.Infrastructure.Auth;

/// <summary>PBKDF2-SHA256, 600k iterations, 128-bit salt. Format: pbkdf2-sha256$iter$salt$hash (base64).</summary>
public static class PasswordHasher
{
    public const int Iterations = 600_000;

    public static string Hash(string password, int iterations = Iterations)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string? stored)
    {
        if (string.IsNullOrEmpty(stored)) { Dummy(password); return false; }
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out var iter) || iter < 1000 || iter > 10_000_000) { Dummy(password); return false; }
        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iter, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException) { return false; }
    }

    private static readonly string DummyHash = Hash("dummy-password-for-timing", Iterations);
    private static void Dummy(string password) => Verify2(password, DummyHash);
    private static void Verify2(string password, string stored)
    {
        var p = stored.Split('$');
        Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(p[2]), int.Parse(p[1]), HashAlgorithmName.SHA256, 32);
    }
}

public static class Totp
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string NewSecret() => Base32Encode(RandomNumberGenerator.GetBytes(20));

    public static long CounterAt(DateTimeOffset t) => t.ToUnixTimeSeconds() / 30;

    public static string Code(string base32Secret, long counter)
    {
        var key = Base32Decode(base32Secret);
        var msg = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        var h = HMACSHA1.HashData(key, msg);
        var off = h[^1] & 0x0f;
        var bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
        return (bin % 1_000_000).ToString("D6");
    }

    /// <summary>Returns the matched counter (for replay protection) or null.</summary>
    public static long? Verify(string base32Secret, string code, DateTimeOffset now, long? lastUsedCounter)
    {
        if (code.Length != 6 || !code.All(char.IsAsciiDigit)) return null;
        var c = CounterAt(now);
        for (var d = -1; d <= 1; d++)
        {
            var cand = c + d;
            if (lastUsedCounter is { } l && cand <= l) continue;
            if (CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(Code(base32Secret, cand)), System.Text.Encoding.ASCII.GetBytes(code)))
                return cand;
        }
        return null;
    }

    public static string Uri(string secret, string account, string issuer) =>
        $"otpauth://totp/{System.Uri.EscapeDataString(issuer)}:{System.Uri.EscapeDataString(account)}?secret={secret}&issuer={System.Uri.EscapeDataString(issuer)}&digits=6&period=30";

    public static string Base32Encode(byte[] data)
    {
        var sb = new System.Text.StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b; bits += 8;
            while (bits >= 5) { sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] Base32Decode(string s)
    {
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var ch in s.TrimEnd('=').ToUpperInvariant())
        {
            var v = Alphabet.IndexOf(ch);
            if (v < 0) continue;
            buffer = (buffer << 5) | v; bits += 5;
            if (bits >= 8) { bytes.Add((byte)((buffer >> (bits - 8)) & 0xff)); bits -= 8; }
        }
        return bytes.ToArray();
    }
}
