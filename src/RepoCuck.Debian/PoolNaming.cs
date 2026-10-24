namespace RepoCuck.Debian;

public static class PoolNaming
{
    public static string Prefix(string package) =>
        package.StartsWith("lib", StringComparison.Ordinal) && package.Length > 3 ? package[..4] : package[..1];

    public static string FileName(string package, string version, string arch, string? collisionSha256 = null)
    {
        var v = version;
        var colon = v.IndexOf(':');
        if (colon >= 0) v = v[(colon + 1)..];
        var name = $"{package}_{v}_{arch}".Replace('/', '_').Replace(':', '_').ToLowerInvariant();
        if (collisionSha256 is not null) name += "+" + collisionSha256[..8];
        const int max = 200 - 4;
        if (name.Length > max) name = name[..max];
        return name + ".deb";
    }

    /// <summary>Path relative to the repository root (the value of the Filename field).</summary>
    public static string RelativePath(string component, string package, string fileName) =>
        $"pool/{component}/{Prefix(package)}/{package}/{fileName}";
}
