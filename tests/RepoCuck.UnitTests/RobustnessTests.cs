using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using RepoCuck.Debian;

namespace RepoCuck.Tests;

public class RobustnessTests
{
    [Fact]
    public void Mutated_debs_never_crash_the_parser_or_escape_with_unexpected_exceptions()
    {
        var seed = DebBuilder.Build("fuzzme", "1.2.3-4", "amd64", "Depends: libc6 (>= 2.34)\nSection: utils");
        var rng = new Random(12345);
        var parsed = 0; var rejected = 0;
        for (var i = 0; i < 4000; i++)
        {
            var data = (byte[])seed.Clone();
            switch (i % 4)
            {
                case 0: for (var k = rng.Next(1, 6); k > 0; k--) data[rng.Next(data.Length)] = (byte)rng.Next(256); break;   // random byte flips
                case 1: data = data[..rng.Next(data.Length)]; break;                                                         // truncation
                case 2: { var pos = rng.Next(60, data.Length - 1); var extra = new byte[rng.Next(1, 40)]; rng.NextBytes(extra); data = [.. data[..pos], .. extra, .. data[pos..]]; break; }   // insertion
                default: for (var k = 0; k < 20; k++) data[rng.Next(Math.Min(120, data.Length))] ^= (byte)(1 << rng.Next(8)); break;   // header-focused flips
            }
            try { using var ms = new MemoryStream(data); DebInspector.Inspect(ms, 1 << 20); parsed++; }
            catch (DebFormatException) { rejected++; }
        }
        Assert.True(rejected > 1000, "most mutations should be rejected cleanly");
        Assert.True(parsed + rejected == 4000);
    }

    [Fact]
    public void Decompression_bomb_in_control_archive_is_rejected_by_ratio_and_size_limits()
    {
        // 40 MiB of zeros inside a tar entry named ./control, gzip-compressed to a few dozen KiB: ratio ~1000:1
        var tar = new MemoryStream();
        using (var w = new TarWriter(tar, leaveOpen: true))
            w.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "./control") { DataStream = new MemoryStream(new byte[40 * 1024 * 1024]) });
        var gz = new MemoryStream();
        using (var z = new GZipStream(gz, CompressionLevel.SmallestSize, true)) z.Write(tar.ToArray());
        Assert.True(gz.Length < 200_000);
        using var o = new MemoryStream();
        o.Write("!<arch>\n"u8);
        DebBuilder.WriteMember(o, "debian-binary", "2.0\n"u8.ToArray());
        DebBuilder.WriteMember(o, "control.tar.gz", gz.ToArray());
        DebBuilder.WriteMember(o, "data.tar.gz", new byte[16]);
        o.Position = 0;
        var e = Assert.Throws<DebFormatException>(() => DebInspector.Inspect(o, 1 << 24));
        Assert.True(e.Code is "decompression_limit" or "control_too_large" or "bad_control_tar", e.Code);
    }

    [Fact]
    public void Oversized_control_file_many_fields_and_huge_values_are_rejected()
    {
        var big = "Package: bigpkg\nVersion: 1\nArchitecture: all\nDescription: x\nHomepage: " + new string('a', 9000) + "\n";
        Assert.Throws<DebFormatException>(() => ControlParser.Parse(Encoding.UTF8.GetBytes(big)));
        var many = new StringBuilder("Package: manyfields\nVersion: 1\nArchitecture: all\nDescription: x\n");
        for (var i = 0; i < 120; i++) many.Append($"X-Field-{i}: v\n");
        Assert.Throws<DebFormatException>(() => ControlParser.Parse(Encoding.UTF8.GetBytes(many.ToString())));
        Assert.Throws<DebFormatException>(() => ControlParser.Parse([0xff, 0xfe, 0x50]));    // invalid UTF-8
    }

    [Fact]
    public void Control_with_embedded_newline_injection_cannot_forge_extra_stanza_or_fields()
    {
        // A "Description" continuation that looks like a new stanza/field must stay inside the Description value
        var c = ControlParser.Parse(Encoding.UTF8.GetBytes(
            "Package: inj\nVersion: 1\nArchitecture: all\nDescription: x\n \n SHA256: forged\n Filename: ../../etc/passwd\n"));
        Assert.Null(c.Get("SHA256")); Assert.Null(c.Get("Filename"));
        var text = Encoding.UTF8.GetString(PackagesWriter.Write([new PackageStanza(c.Fields, "pool/main/i/inj/inj_1_all.deb", 3, "aa", "bb")]));
        Assert.Equal(1, text.Split("\nFilename: ").Length - 1 + (text.StartsWith("Filename: ") ? 1 : 0));
        Assert.DoesNotContain("\n\n", text.TrimEnd('\n'));
    }

    [Fact]
    public void Ar_reader_rejects_negative_hex_and_oversized_sizes_and_too_many_members()
    {
        using var ms = new MemoryStream();
        ms.Write("!<arch>\n"u8);
        for (var i = 0; i < 20; i++) DebBuilder.WriteMember(ms, "m" + i, [1, 2]);
        ms.Position = 0;
        Assert.Equal("too_many_members", Assert.Throws<DebFormatException>(() => ArReader.ReadMembers(ms, 1000)).Code);

        foreach (var badSize in new[] { "-5        ", "0x10      ", "          ", "1e3       " })
        {
            var hdr = "x/".PadRight(16) + "0".PadRight(12) + "0".PadRight(6) + "0".PadRight(6) + "100644".PadRight(8) + badSize + "`\n";
            var bytes = Encoding.ASCII.GetBytes("!<arch>\n" + hdr + "data");
            using var s = new MemoryStream(bytes);
            Assert.Equal("bad_size", Assert.Throws<DebFormatException>(() => ArReader.ReadMembers(s, 1000)).Code);
        }
    }
}
