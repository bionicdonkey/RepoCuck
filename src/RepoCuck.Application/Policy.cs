using RepoCuck.Debian;

namespace RepoCuck.Application;

public static class DefaultReservedNames
{
    public static readonly string[] Names =
    [
        "libc6", "libc-bin", "libc6-dev", "libgcc-s1", "libstdc++6", "base-files", "base-passwd", "bash", "dash",
        "coreutils", "util-linux", "login", "passwd", "sudo", "su", "apt", "apt-utils", "dpkg", "gnupg", "gpg",
        "openssh-server", "openssh-client", "openssl", "libssl3", "ca-certificates", "systemd", "systemd-sysv",
        "udev", "init", "initramfs-tools", "linux-image-generic", "linux-image-amd64", "grub-pc", "grub-efi-amd64",
        "shim-signed", "libpam0g", "libpam-modules", "libpam-runtime", "openssh-sftp-server", "ssh", "e2fsprogs",
        "mount", "tar", "gzip", "bzip2", "xz-utils", "zlib1g", "libsystemd0", "dbus", "network-manager", "netplan.io",
        "ifupdown", "iproute2", "iptables", "nftables", "resolvconf", "libcurl4", "curl", "wget", "python3",
        "perl", "perl-base", "debconf", "debianutils", "findutils", "grep", "sed", "gawk", "bsdutils", "ubuntu-minimal",
        "ubuntu-standard", "ubuntu-desktop", "debian-archive-keyring", "ubuntu-keyring", "tzdata", "cron", "rsyslog"
    ];
}

public sealed record PolicyVerdict(bool Quarantine, string? Reason);

public sealed class PackagePolicy(PolicyOptions options, ISet<string>? extraReserved = null)
{
    private readonly HashSet<string> _reserved = BuildSet(options, extraReserved);

    private static HashSet<string> BuildSet(PolicyOptions o, ISet<string>? extra)
    {
        var set = new HashSet<string>(DefaultReservedNames.Names, StringComparer.OrdinalIgnoreCase);
        foreach (var n in o.ReservedNames.Split([',', ';', '\n', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            set.Add(n);
        if (extra is not null) foreach (var n in extra) set.Add(n);
        return set;
    }

    public PolicyVerdict Evaluate(ControlFile c)
    {
        if (_reserved.Contains(c.Package)) return new(true, "reserved_name");
        foreach (var rel in new[] { "Provides", "Replaces", "Conflicts", "Breaks" })
        {
            var v = c.Get(rel);
            if (v is null) continue;
            foreach (var part in v.Split([',', '|']))
            {
                var name = part.Trim();
                var cut = name.IndexOfAny([' ', '(', ':', '|']);
                if (cut >= 0) name = name[..cut];
                if (name.Length > 0 && _reserved.Contains(name)) return new(true, "reserved_name:" + rel.ToLowerInvariant());
            }
        }
        if (!options.AllowEpoch && DebianVersion.TryParse(c.Version, out var ver) && ver!.Epoch >= 1)
            return new(true, "epoch");
        return new(false, null);
    }
}

public static class Architectures
{
    public static string[] Normalize(IEnumerable<string>? input, IEnumerable<string> allowList)
    {
        var allow = new HashSet<string>(allowList, StringComparer.Ordinal);
        return (input ?? []).Select(a => a.Trim().ToLowerInvariant()).Where(allow.Contains).Distinct().Order(StringComparer.Ordinal).ToArray();
    }

    public static string[] ParseList(string csv) =>
        csv.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
           .Select(a => a.ToLowerInvariant()).Distinct().ToArray();
}

public static class GlobMatcher
{
    public static bool IsMatch(string pattern, string name)
    {
        foreach (var p in pattern.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (Match(p, name)) return true;
        return false;
    }

    private static bool Match(string pattern, string text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (char.ToLowerInvariant(pattern[p]) == char.ToLowerInvariant(text[t]) || pattern[p] == '?')) { p++; t++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = t; }
            else if (star >= 0) { p = star + 1; t = ++mark; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}

public static class RepoRef
{
    /// <summary>Parses owner/name, https://github.com/owner/name(.git)?, or git@github.com:owner/name(.git)?</summary>
    public static bool TryParse(string? input, out string owner, out string name)
    {
        owner = name = "";
        if (string.IsNullOrWhiteSpace(input)) return false;
        var s = input.Trim();
        if (s.StartsWith("git@github.com:", StringComparison.OrdinalIgnoreCase)) s = s["git@github.com:".Length..];
        else if (s.StartsWith("https://github.com/", StringComparison.OrdinalIgnoreCase)) s = s["https://github.com/".Length..];
        else if (s.StartsWith("http://github.com/", StringComparison.OrdinalIgnoreCase)) s = s["http://github.com/".Length..];
        s = s.Trim('/');
        if (s.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) s = s[..^4];
        var parts = s.Split('/');
        if (parts.Length < 2) return false;
        if (s.Contains("://") || parts.Length > 2 && !input.Contains("github.com", StringComparison.OrdinalIgnoreCase)) return false;
        owner = parts[0]; name = parts[1];
        return IsSafe(owner) && IsSafe(name);
    }

    private static bool IsSafe(string x) =>
        x.Length is > 0 and <= 100 && x.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') && x is not ("." or "..");
}
