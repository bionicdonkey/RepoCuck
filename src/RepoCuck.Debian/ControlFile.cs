using System.Text;
using System.Text.RegularExpressions;

namespace RepoCuck.Debian;

/// <summary>Ordered, sanitised control fields. Multi-line values keep '\n' between lines (Description) or are folded.</summary>
public sealed class ControlFile
{
    public List<KeyValuePair<string, string>> Fields { get; } = new();

    public string? Get(string name)
    {
        foreach (var f in Fields)
            if (f.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return f.Value;
        return null;
    }

    public string Package => Get("Package") ?? "";
    public string Version => Get("Version") ?? "";
    public string Architecture => Get("Architecture") ?? "";
    public string Description => Get("Description") ?? "";
}

public static partial class ControlParser
{
    public const int MaxFields = 100;
    public const int MaxValueBytes = 8 * 1024;
    public const int MaxDescriptionBytes = 32 * 1024;
    public const int MaxDependsBytes = 16 * 1024;

    private static readonly HashSet<string> Dropped = new(StringComparer.OrdinalIgnoreCase)
    {
        "Filename", "Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Description-md5",
        "Status", "Config-Version", "Conffiles", "Tag"
    };

    private static readonly HashSet<string> MultiLine = new(StringComparer.OrdinalIgnoreCase) { "Description" };

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9-]*$")] private static partial Regex FieldName();
    [GeneratedRegex("^[a-z0-9][a-z0-9+.-]+$")] private static partial Regex PackageName();
    [GeneratedRegex("^[0-9][A-Za-z0-9.+~:-]*$")] private static partial Regex VersionRx();
    [GeneratedRegex("^(all|[a-z0-9][a-z0-9-]*)$")] private static partial Regex ArchRx();

    /// <summary>Parses and sanitises a binary control file. Throws <see cref="DebFormatException"/> with code invalid_control.</summary>
    public static ControlFile Parse(ReadOnlySpan<byte> raw)
    {
        string text;
        try { text = new UTF8Encoding(false, true).GetString(raw); }
        catch (DecoderFallbackException) { throw Bad("control is not valid UTF-8"); }

        var result = new ControlFile();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? name = null;
        List<string>? lines = null;

        void Flush()
        {
            if (name is null || lines is null) return;
            var multi = MultiLine.Contains(name);
            var value = multi ? string.Join('\n', lines) : string.Join(' ', lines.Select(l => l.Trim()));
            value = value.Trim();
            if (!multi) value = CollapseSpaces(value);
            var limit = multi ? MaxDescriptionBytes : (name.Contains("Depends", StringComparison.OrdinalIgnoreCase)
                || name is "Recommends" or "Suggests" or "Conflicts" or "Breaks" or "Replaces" or "Provides" or "Enhances"
                ? MaxDependsBytes : MaxValueBytes);
            if (Encoding.UTF8.GetByteCount(value) > limit) throw Bad($"field {name} too large");
            if (Dropped.Contains(name)) { name = null; lines = null; return; }
            if (!seen.Add(name)) throw Bad($"duplicate field {name}");
            result.Fields.Add(new(name, value));
            if (result.Fields.Count > MaxFields) throw Bad("too many fields");
            name = null; lines = null;
        }

        foreach (var line in text.Split('\n'))
        {
            if (line.Length == 0)
            {
                if (name is null) continue;
                // a blank line ends the stanza; only the first stanza is used
                Flush();
                break;
            }
            foreach (var ch in line)
                if ((ch < 0x20 && ch != '\t') || ch == 0x7f)
                    throw Bad("control characters in control file");
            if (line[0] is ' ' or '\t')
            {
                if (name is null || lines is null) throw Bad("continuation without field");
                var cont = line[1..];
                lines.Add(MultiLine.Contains(name) ? cont.TrimEnd() : cont);
                continue;
            }
            Flush();
            var colon = line.IndexOf(':');
            if (colon <= 0) throw Bad("malformed line");
            var n = line[..colon];
            if (!FieldName().IsMatch(n)) throw Bad($"bad field name '{n}'");
            name = n;
            lines = new List<string> { line[(colon + 1)..].Trim() };
        }
        Flush();

        Validate(result);
        return result;
    }

    private static void Validate(ControlFile c)
    {
        foreach (var req in new[] { "Package", "Version", "Architecture", "Description" })
            if (string.IsNullOrWhiteSpace(c.Get(req))) throw Bad($"missing required field {req}");
        var pkg = c.Package;
        if (pkg.Length > 100 || !PackageName().IsMatch(pkg)) throw Bad("invalid Package");
        if (!VersionRx().IsMatch(c.Version) || !DebianVersion.TryParse(c.Version, out _)) throw Bad("invalid Version");
        var arch = c.Architecture;
        if (!ArchRx().IsMatch(arch) || arch is "source" or "any") throw Bad("invalid Architecture");
        var inst = c.Get("Installed-Size");
        if (inst is not null && !(inst.Length > 0 && inst.All(char.IsAsciiDigit))) throw Bad("invalid Installed-Size");
        var ma = c.Get("Multi-Arch");
        if (ma is not null && ma is not ("no" or "same" or "foreign" or "allowed")) throw Bad("invalid Multi-Arch");
        // Empty Maintainer is accepted but omitted from the index.
        c.Fields.RemoveAll(f => f.Key.Equals("Maintainer", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(f.Value));
    }

    private static string CollapseSpaces(string s)
    {
        if (!s.Contains("  ")) return s;
        var sb = new StringBuilder(s.Length);
        var prev = false;
        foreach (var ch in s)
        {
            var sp = ch == ' ';
            if (sp && prev) continue;
            sb.Append(ch);
            prev = sp;
        }
        return sb.ToString();
    }

    private static DebFormatException Bad(string msg) => new("invalid_control", msg);
}
