namespace RepoCuck.Debian;

/// <summary>Debian policy §5.6.12 version ordering, matching dpkg's verrevcmp.</summary>
public sealed class DebianVersion : IComparable<DebianVersion>, IEquatable<DebianVersion>
{
    public int Epoch { get; }
    public string Upstream { get; }
    public string Revision { get; }
    public string Original { get; }

    private DebianVersion(string original, int epoch, string upstream, string revision)
    {
        Original = original;
        Epoch = epoch;
        Upstream = upstream;
        Revision = revision;
    }

    public static DebianVersion Parse(string version)
    {
        if (!TryParse(version, out var v)) throw new FormatException($"Invalid Debian version '{version}'.");
        return v!;
    }

    public static bool TryParse(string? version, out DebianVersion? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(version) || version.Length > 128) return false;
        var s = version.Trim();
        var epoch = 0;
        var colon = s.IndexOf(':');
        if (colon >= 0)
        {
            if (colon == 0 || !int.TryParse(s.AsSpan(0, colon), out epoch) || epoch < 0) return false;
            s = s[(colon + 1)..];
        }
        var upstream = s;
        var revision = "";
        var dash = s.LastIndexOf('-');
        if (dash >= 0)
        {
            upstream = s[..dash];
            revision = s[(dash + 1)..];
            if (upstream.Length == 0 || revision.Length == 0) return false;
        }
        if (upstream.Length == 0 || !char.IsAsciiDigit(upstream[0])) return false;
        foreach (var c in upstream)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '+' or '~' or ':' or '-')) return false;
        foreach (var c in revision)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '.' or '+' or '~')) return false;
        result = new DebianVersion(version.Trim(), epoch, upstream, revision);
        return true;
    }

    public static int Compare(string a, string b) => Parse(a).CompareTo(Parse(b));

    public int CompareTo(DebianVersion? other)
    {
        if (other is null) return 1;
        if (Epoch != other.Epoch) return Epoch.CompareTo(other.Epoch);
        var c = VerRevCmp(Upstream, other.Upstream);
        if (c != 0) return c;
        return VerRevCmp(Revision, other.Revision);
    }

    private static int Order(string s, int i)
    {
        if (i >= s.Length) return 0;
        var c = s[i];
        if (char.IsAsciiDigit(c)) return 0;
        if (char.IsAsciiLetter(c)) return c;
        if (c == '~') return -1;
        return c + 256;
    }

    internal static int VerRevCmp(string a, string b)
    {
        int i = 0, j = 0;
        while (i < a.Length || j < b.Length)
        {
            while ((i < a.Length && !char.IsAsciiDigit(a[i])) || (j < b.Length && !char.IsAsciiDigit(b[j])))
            {
                var ac = Order(a, i);
                var bc = Order(b, j);
                if (ac != bc) return Math.Sign(ac - bc);
                if (i < a.Length) i++;
                if (j < b.Length) j++;
            }
            while (i < a.Length && a[i] == '0') i++;
            while (j < b.Length && b[j] == '0') j++;
            var firstDiff = 0;
            while (i < a.Length && char.IsAsciiDigit(a[i]) && j < b.Length && char.IsAsciiDigit(b[j]))
            {
                if (firstDiff == 0) firstDiff = Math.Sign(a[i] - b[j]);
                i++;
                j++;
            }
            if (i < a.Length && char.IsAsciiDigit(a[i])) return 1;
            if (j < b.Length && char.IsAsciiDigit(b[j])) return -1;
            if (firstDiff != 0) return firstDiff;
        }
        return 0;
    }

    public bool Equals(DebianVersion? other) => other is not null && CompareTo(other) == 0;
    public override bool Equals(object? obj) => obj is DebianVersion v && Equals(v);
    public override int GetHashCode() => HashCode.Combine(Epoch, Upstream.TrimStart('0'), Revision.TrimStart('0'));
    public override string ToString() => Original;
    public static bool operator <(DebianVersion a, DebianVersion b) => a.CompareTo(b) < 0;
    public static bool operator >(DebianVersion a, DebianVersion b) => a.CompareTo(b) > 0;
}
