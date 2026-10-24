using System.Text;
using RepoCuck.Debian;

namespace RepoCuck.Tests;

public class DebianVersionTests
{
    [Theory]
    [InlineData("1.0", "1.0", 0)]
    [InlineData("1.0", "1.1", -1)]
    [InlineData("1.10", "1.9", 1)]
    [InlineData("1.0~rc1", "1.0", -1)]
    [InlineData("1.0~rc1", "1.0~rc2", -1)]
    [InlineData("1.0~~", "1.0~", -1)]
    [InlineData("1.0", "1.0a", -1)]
    [InlineData("1.0~rc1", "1.0a", -1)]
    [InlineData("1.0-1", "1.0-1+b1", -1)]
    [InlineData("1.0-1", "1.0-2", -1)]
    [InlineData("1:0.1", "9.9", 1)]
    [InlineData("0:1.0", "1.0", 0)]
    [InlineData("1.0+dfsg", "1.0", 1)]
    [InlineData("1.0.1", "1.0", 1)]
    [InlineData("1.0-0", "1.0", 0)]
    [InlineData("007", "7", 0)]
    [InlineData("1.0a", "1.0b", -1)]
    [InlineData("1.0+", "1.0.", -1)]
    [InlineData("2.0", "10.0", -1)]
    [InlineData("1.2.3-4ubuntu1", "1.2.3-4", 1)]
    [InlineData("1.2.3-4ubuntu1", "1.2.3-4ubuntu2", -1)]
    [InlineData("1.0~beta", "1.0~", 1)]
    [InlineData("1.0-1~bpo1", "1.0-1", -1)]
    [InlineData("2:1.0", "1:9.9", 1)]
    [InlineData("1.0.0.0", "1.0", 1)]
    public void Compares_like_dpkg(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(DebianVersion.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(DebianVersion.Compare(b, a)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("1.0-")]
    [InlineData(":1.0")]
    [InlineData("1.0 2")]
    public void Rejects_invalid(string v) => Assert.False(DebianVersion.TryParse(v, out _));

    [Fact]
    public void Ordering_is_transitive_over_a_corpus()
    {
        var vs = new[] { "0.9", "1.0~rc1", "1.0", "1.0+b1", "1.0-1", "1.0-1+b1", "1.0a", "1.1", "1:0.1", "2:0.0" }
            .Select(DebianVersion.Parse).ToList();
        foreach (var a in vs) foreach (var b in vs) foreach (var c in vs)
            if (a.CompareTo(b) <= 0 && b.CompareTo(c) <= 0) Assert.True(a.CompareTo(c) <= 0);
    }
}

public class ArAndControlTests
{
    [Fact]
    public void Parses_valid_deb()
    {
        var deb = DebBuilder.Build("ripgrep", "14.1.1-1", "amd64", "Depends: libc6 (>= 2.34)\nSection: utils");
        using var ms = new MemoryStream(deb);
        var info = DebInspector.Inspect(ms, 1 << 20);
        Assert.Equal("ripgrep", info.Control.Package);
        Assert.Equal("14.1.1-1", info.Control.Version);
        Assert.Equal("amd64", info.Control.Architecture);
        Assert.Equal("libc6 (>= 2.34)", info.Control.Get("Depends"));
        Assert.Equal("A test package\nsecond line", info.Control.Description);
    }

    [Fact]
    public void Uncompressed_control_tar_is_supported()
    {
        var deb = DebBuilder.BuildRaw(Encoding.UTF8.GetBytes("Package: a1\nVersion: 1\nArchitecture: all\nDescription: x\n"), "none");
        using var ms = new MemoryStream(deb);
        Assert.Equal("a1", DebInspector.Inspect(ms, 1 << 20).Control.Package);
    }

    [Fact]
    public void Missing_maintainer_is_accepted_and_empty_maintainer_dropped()
    {
        var deb = DebBuilder.Build("a1", "1", "all", maintainer: "");
        using var ms = new MemoryStream(deb);
        var info = DebInspector.Inspect(ms, 1 << 20);
        Assert.Null(info.Control.Get("Maintainer"));
    }

    [Fact]
    public void Rejects_bad_magic()
    {
        using var ms = new MemoryStream(Encoding.ASCII.GetBytes("not an archive at all"));
        var e = Assert.Throws<DebFormatException>(() => DebInspector.Inspect(ms, 1 << 20));
        Assert.Equal("not_ar", e.Code);
    }

    [Fact]
    public void Rejects_truncated_member()
    {
        var deb = DebBuilder.Build("a1", "1", "all");
        using var ms = new MemoryStream(deb[..(deb.Length - 40)]);
        Assert.Throws<DebFormatException>(() => DebInspector.Inspect(ms, 1 << 20));
    }

    [Fact]
    public void Rejects_unknown_debian_binary_version()
    {
        var deb = DebBuilder.BuildRaw(Encoding.UTF8.GetBytes("Package: a1\nVersion: 1\nArchitecture: all\nDescription: x\n"), "gz", "3.0\n");
        using var ms = new MemoryStream(deb);
        Assert.Equal("unsupported_format", Assert.Throws<DebFormatException>(() => DebInspector.Inspect(ms, 1 << 20)).Code);
    }

    [Fact]
    public void Rejects_oversized_member()
    {
        var deb = DebBuilder.Build("a1", "1", "all");
        using var ms = new MemoryStream(deb);
        Assert.Throws<DebFormatException>(() => ArReader.ReadMembers(ms, 10));
    }

    [Theory]
    [InlineData("Package: A\nVersion: 1\nArchitecture: all\nDescription: x\n")] // uppercase package
    [InlineData("Package: a\nVersion: 1\nArchitecture: all\nDescription: x\n")] // 1-char package
    [InlineData("Package: ab\nVersion: x1\nArchitecture: all\nDescription: x\n")]
    [InlineData("Package: ab\nVersion: 1\nArchitecture: source\nDescription: x\n")]
    [InlineData("Package: ab\nVersion: 1\nArchitecture: any\nDescription: x\n")]
    [InlineData("Package: ab\nVersion: 1\nArchitecture: all\n")] // no description
    [InlineData("Package: ab\nVersion: 1\nArchitecture: all\nDescription: x\nMulti-Arch: bogus\n")]
    [InlineData("Package: ab\nVersion: 1\nArchitecture: all\nDescription: x\nInstalled-Size: -1\n")]
    [InlineData("Package: ab\nVersion: 1\nArchitecture: all\nDescription: x\nPackage: ac\n")] // duplicate
    [InlineData("Package: ab\nVersion: 1\nArchitecture: all\nDescription: x\u0001y\n")] // control char
    [InlineData("Package: ab\nVersion: 1\nArchitecture: all\nDescription: x\nbad name: v\n")]
    public void Rejects_invalid_control(string control)
    {
        var e = Assert.Throws<DebFormatException>(() => ControlParser.Parse(Encoding.UTF8.GetBytes(control)));
        Assert.Equal("invalid_control", e.Code);
    }

    [Fact]
    public void Drops_computed_fields_and_folds_dependencies()
    {
        var c = ControlParser.Parse(Encoding.UTF8.GetBytes(
            "Package: abc\nVersion: 1.0\nArchitecture: amd64\nDescription: d\nSHA256: evil\nFilename: ../x\nSize: 1\nTag: foo\nDepends: a,\n b,\n  c\n"));
        Assert.Null(c.Get("SHA256")); Assert.Null(c.Get("Filename")); Assert.Null(c.Get("Size")); Assert.Null(c.Get("Tag"));
        Assert.Equal("a, b, c", c.Get("Depends"));
    }

    [Fact]
    public void Description_preserves_paragraph_markers()
    {
        var c = ControlParser.Parse(Encoding.UTF8.GetBytes(
            "Package: abc\nVersion: 1.0\nArchitecture: amd64\nDescription: short\n long one\n .\n long two\n"));
        Assert.Equal("short\nlong one\n.\nlong two", c.Description);
    }
}

public class PoolAndIndexTests
{
    [Theory]
    [InlineData("ripgrep", "r")]
    [InlineData("libfoo", "libf")]
    [InlineData("lib", "l")]
    public void Pool_prefix(string pkg, string prefix) => Assert.Equal(prefix, PoolNaming.Prefix(pkg));

    [Fact]
    public void Filename_strips_epoch_and_adds_collision_suffix()
    {
        Assert.Equal("foo_1.0-1_amd64.deb", PoolNaming.FileName("foo", "2:1.0-1", "amd64"));
        Assert.Equal("foo_1.0-1_amd64+abcdef12.deb", PoolNaming.FileName("foo", "1.0-1", "amd64", "abcdef1234"));
        Assert.Equal("pool/main/r/ripgrep/ripgrep_1_amd64.deb", PoolNaming.RelativePath("main", "ripgrep", "ripgrep_1_amd64.deb"));
    }

    [Fact]
    public void Packages_output_is_stable_and_ends_with_one_newline()
    {
        var control = new List<KeyValuePair<string, string>>
        {
            new("Package", "foo"), new("Version", "1"), new("Architecture", "amd64"),
            new("Description", "short\nlong\n.\nmore"),
        };
        var a = new PackageStanza(control, "pool/main/f/foo/foo_1_amd64.deb", 10, "aa", "bb");
        var text = Encoding.UTF8.GetString(PackagesWriter.Write([a, a with { Filename = "x" }]));
        var expected =
            "Package: foo\nVersion: 1\nArchitecture: amd64\nDescription: short\n long\n .\n more\n" +
            "Filename: pool/main/f/foo/foo_1_amd64.deb\nSize: 10\nSHA256: aa\nSHA512: bb\n\n" +
            "Package: foo\nVersion: 1\nArchitecture: amd64\nDescription: short\n long\n .\n more\n" +
            "Filename: x\nSize: 10\nSHA256: aa\nSHA512: bb\n";
        Assert.Equal(expected, text);
    }

    [Fact]
    public void Release_contains_required_fields()
    {
        var d = new DateTimeOffset(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);
        var text = Encoding.UTF8.GetString(ReleaseWriter.WriteRelease("RepoCuck", "RepoCuck", "stable", 42,
            ["all", "amd64"], "main", "desc", d, d.AddDays(7), false,
            [new ReleaseFile("main/binary-amd64/Packages", "ab", 5)]));
        Assert.Contains("Date: Sat, 24 Oct 2026 12:00:00 UTC\n", text);
        Assert.Contains("Valid-Until: Sat, 31 Oct 2026 12:00:00 UTC\n", text);
        Assert.Contains("Acquire-By-Hash: yes\n", text);
        Assert.Contains("Architectures: all amd64\n", text);
        Assert.Contains("SHA256:\n ab          5 main/binary-amd64/Packages\n", text);
        Assert.DoesNotContain("MD5Sum", text);
    }
}
