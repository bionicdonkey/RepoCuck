using System.Globalization;
using System.Text;

namespace RepoCuck.Debian;

public sealed record PackageStanza(
    IReadOnlyList<KeyValuePair<string, string>> Control,
    string Filename,
    long Size,
    string Sha256,
    string Sha512);

public static class PackagesWriter
{
    /// <summary>Writes a Packages index. Caller supplies stanzas already in the desired deterministic order.</summary>
    public static byte[] Write(IEnumerable<PackageStanza> stanzas)
    {
        var sb = new StringBuilder();
        var first = true;
        foreach (var s in stanzas)
        {
            if (!first) sb.Append('\n');
            first = false;
            foreach (var (k, v) in s.Control)
            {
                sb.Append(k).Append(':');
                if (k.Equals("Description", StringComparison.OrdinalIgnoreCase))
                {
                    var lines = v.Split('\n');
                    sb.Append(' ').Append(lines[0]).Append('\n');
                    for (var i = 1; i < lines.Length; i++)
                    {
                        var l = lines[i];
                        sb.Append(' ').Append(l.Length == 0 ? "." : l).Append('\n');
                    }
                }
                else sb.Append(' ').Append(v).Append('\n');
            }
            sb.Append("Filename: ").Append(s.Filename).Append('\n');
            sb.Append("Size: ").Append(s.Size.ToString(CultureInfo.InvariantCulture)).Append('\n');
            sb.Append("SHA256: ").Append(s.Sha256).Append('\n');
            sb.Append("SHA512: ").Append(s.Sha512).Append('\n');
        }
        return new UTF8Encoding(false).GetBytes(sb.ToString());
    }
}

public sealed record ReleaseFile(string Path, string Sha256, long Size);

public static class ReleaseWriter
{
    public static string FormatDate(DateTimeOffset d) =>
        d.UtcDateTime.ToString("ddd, dd MMM yyyy HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    public static byte[] WriteRelease(
        string origin, string label, string suite, long version, IEnumerable<string> architectures,
        string component, string description, DateTimeOffset date, DateTimeOffset validUntil,
        bool notAutomatic, IEnumerable<ReleaseFile> files)
    {
        var sb = new StringBuilder();
        sb.Append("Origin: ").Append(origin).Append('\n');
        sb.Append("Label: ").Append(label).Append('\n');
        sb.Append("Suite: ").Append(suite).Append('\n');
        sb.Append("Codename: ").Append(suite).Append('\n');
        sb.Append("Version: ").Append(version.ToString(CultureInfo.InvariantCulture)).Append('\n');
        sb.Append("Architectures: ").Append(string.Join(' ', architectures)).Append('\n');
        sb.Append("Components: ").Append(component).Append('\n');
        sb.Append("Description: ").Append(description).Append('\n');
        sb.Append("Date: ").Append(FormatDate(date)).Append('\n');
        sb.Append("Valid-Until: ").Append(FormatDate(validUntil)).Append('\n');
        sb.Append("Acquire-By-Hash: yes\n");
        sb.Append("No-Support-for-Architecture-all: Packages\n");
        if (notAutomatic) sb.Append("NotAutomatic: yes\nButAutomaticUpgrades: yes\n");
        sb.Append("SHA256:\n");
        foreach (var f in files.OrderBy(f => f.Path, StringComparer.Ordinal))
            sb.Append(' ').Append(f.Sha256).Append(' ').Append(f.Size.ToString(CultureInfo.InvariantCulture)
                .PadLeft(10)).Append(' ').Append(f.Path).Append('\n');
        return new UTF8Encoding(false).GetBytes(sb.ToString());
    }

    public static byte[] WriteArchRelease(string origin, string label, string suite, long version,
        string component, string arch)
    {
        var s = $"Archive: {suite}\nOrigin: {origin}\nLabel: {label}\nVersion: {version}\n" +
                $"Acquire-By-Hash: yes\nComponent: {component}\nArchitecture: {arch}\n";
        return new UTF8Encoding(false).GetBytes(s);
    }
}
