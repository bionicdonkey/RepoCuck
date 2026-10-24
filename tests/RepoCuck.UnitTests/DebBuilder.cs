using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace RepoCuck.Tests;

/// <summary>Builds minimal but structurally valid .deb files for tests.</summary>
public static class DebBuilder
{
    public static byte[] Build(string package, string version, string arch, string? extraControl = null,
        string compression = "gz", string? maintainer = "Test <t@example.com>", string description = "A test package\n second line")
    {
        var sb = new StringBuilder();
        sb.Append($"Package: {package}\nVersion: {version}\nArchitecture: {arch}\n");
        if (maintainer is not null) sb.Append($"Maintainer: {maintainer}\n");
        sb.Append("Installed-Size: 10\n");
        sb.Append($"Description: {description}\n");
        if (extraControl is not null) sb.Append(extraControl.TrimEnd('\n')).Append('\n');
        return BuildRaw(Encoding.UTF8.GetBytes(sb.ToString()), compression);
    }

    public static byte[] BuildRaw(byte[] control, string compression = "gz", string debianBinary = "2.0\n")
    {
        var tar = new MemoryStream();
        using (var w = new TarWriter(tar, leaveOpen: true))
        {
            var e = new PaxTarEntry(TarEntryType.RegularFile, "./control") { DataStream = new MemoryStream(control) };
            w.WriteEntry(e);
        }
        var tarBytes = tar.ToArray();
        byte[] ctrl;
        string name;
        switch (compression)
        {
            case "gz":
                var ms = new MemoryStream();
                using (var gz = new GZipStream(ms, CompressionLevel.Optimal, true)) gz.Write(tarBytes);
                ctrl = ms.ToArray(); name = "control.tar.gz"; break;
            case "none": ctrl = tarBytes; name = "control.tar"; break;
            default: throw new ArgumentException(compression);
        }
        var data = new byte[64];
        using var o = new MemoryStream();
        o.Write("!<arch>\n"u8);
        WriteMember(o, "debian-binary", Encoding.ASCII.GetBytes(debianBinary));
        WriteMember(o, name, ctrl);
        WriteMember(o, "data.tar.gz", data);
        return o.ToArray();
    }

    public static void WriteMember(Stream o, string name, byte[] content)
    {
        var hdr = new StringBuilder();
        hdr.Append((name + "/").PadRight(16)).Append("0".PadRight(12)).Append("0".PadRight(6)).Append("0".PadRight(6))
           .Append("100644".PadRight(8)).Append(content.Length.ToString().PadRight(10)).Append("`\n");
        o.Write(Encoding.ASCII.GetBytes(hdr.ToString()));
        o.Write(content);
        if (content.Length % 2 == 1) o.WriteByte((byte)'\n');
    }
}
