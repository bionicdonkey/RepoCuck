using System.Text;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Infrastructure.Auth;

namespace RepoCuck.Tests;

public class ApplicationTests
{
    [Theory]
    [InlineData("owner/name", true, "owner", "name")]
    [InlineData("https://github.com/BurntSushi/ripgrep", true, "BurntSushi", "ripgrep")]
    [InlineData("https://github.com/BurntSushi/ripgrep.git", true, "BurntSushi", "ripgrep")]
    [InlineData("https://github.com/BurntSushi/ripgrep/", true, "BurntSushi", "ripgrep")]
    [InlineData("git@github.com:BurntSushi/ripgrep.git", true, "BurntSushi", "ripgrep")]
    [InlineData("http://github.com/a/b", true, "a", "b")]
    [InlineData("a.b-c/d_e.f", true, "a.b-c", "d_e.f")]
    [InlineData("", false, "", "")]
    [InlineData("justaname", false, "", "")]
    [InlineData("../etc/passwd", false, "", "")]
    [InlineData("a/../b", false, "", "")]
    [InlineData("https://evil.example/a/b", false, "", "")]
    [InlineData("a/b c", false, "", "")]
    [InlineData("a/b?x=1", false, "", "")]
    public void RepoRef_parsing(string input, bool ok, string owner, string name)
    {
        Assert.Equal(ok, RepoRef.TryParse(input, out var o, out var n));
        if (ok) { Assert.Equal(owner, o); Assert.Equal(name, n); }
    }

    [Theory]
    [InlineData("*.deb", "tool_1.0_amd64.deb", true)]
    [InlineData("*.deb", "TOOL.DEB", true)]
    [InlineData("*.deb", "tool.deb.sig", false)]
    [InlineData("tool_*_amd64.deb", "tool_1.0_amd64.deb", true)]
    [InlineData("tool_*_amd64.deb", "tool_1.0_arm64.deb", false)]
    [InlineData("*.deb,*.udeb", "x.udeb", true)]
    [InlineData("t?ol.deb", "tool.deb", true)]
    [InlineData("*", "anything", true)]
    public void Glob_matching(string pattern, string name, bool expected) => Assert.Equal(expected, GlobMatcher.IsMatch(pattern, name));

    [Fact]
    public void Architectures_are_normalised_against_the_allow_list()
    {
        var allow = new[] { "amd64", "arm64", "armhf" };
        Assert.Equal(["amd64", "arm64"], Architectures.Normalize(["ARM64", " amd64 ", "amd64", "sparc"], allow));
        Assert.Empty(Architectures.Normalize(null, allow));
        Assert.Equal(["a", "b"], Architectures.ParseList("a, b;a"));
    }

    private static ControlFile Ctl(string text) => ControlParser.Parse(Encoding.UTF8.GetBytes(text));

    [Fact]
    public void Policy_flags_reserved_names_relationships_and_epochs()
    {
        var p = new PackagePolicy(new PolicyOptions { ReservedNames = "custom-critical" });
        Assert.True(p.Evaluate(Ctl("Package: libc6\nVersion: 1\nArchitecture: all\nDescription: x\n")).Quarantine);
        Assert.True(p.Evaluate(Ctl("Package: LIBC6x\nVersion: 1\nArchitecture: all\nDescription: x\n".ToLowerInvariant().Replace("libc6x", "custom-critical"))).Quarantine);
        Assert.True(p.Evaluate(Ctl("Package: ok-pkg\nVersion: 1\nArchitecture: all\nDescription: x\nReplaces: openssh-server (<< 2), foo\n")).Quarantine);
        Assert.True(p.Evaluate(Ctl("Package: ok-pkg\nVersion: 1\nArchitecture: all\nDescription: x\nProvides: foo | sudo\n")).Quarantine);
        Assert.True(p.Evaluate(Ctl("Package: ok-pkg\nVersion: 1\nArchitecture: all\nDescription: x\nConflicts: apt:any\n")).Quarantine);
        var epoch = p.Evaluate(Ctl("Package: ok-pkg\nVersion: 3:1.0\nArchitecture: all\nDescription: x\n"));
        Assert.True(epoch.Quarantine); Assert.Equal("epoch", epoch.Reason);
        Assert.False(p.Evaluate(Ctl("Package: ok-pkg\nVersion: 1.0\nArchitecture: all\nDescription: x\nProvides: virtual-thing\nDepends: libc6\n")).Quarantine);
        Assert.False(new PackagePolicy(new PolicyOptions { AllowEpoch = true }).Evaluate(Ctl("Package: ok-pkg\nVersion: 3:1.0\nArchitecture: all\nDescription: x\n")).Quarantine);
    }

    [Fact]
    public void Password_hashing_roundtrip_and_format()
    {
        var h = PasswordHasher.Hash("correct horse battery staple", 1000);
        Assert.StartsWith("pbkdf2-sha256$1000$", h);
        Assert.True(PasswordHasher.Verify("correct horse battery staple", h));
        Assert.False(PasswordHasher.Verify("wrong", h));
        Assert.False(PasswordHasher.Verify("x", null));
        Assert.False(PasswordHasher.Verify("x", "garbage"));
        Assert.NotEqual(PasswordHasher.Hash("same", 1000), PasswordHasher.Hash("same", 1000));   // salted
    }

    [Fact]
    public void Totp_matches_rfc6238_vectors_and_rejects_replay()
    {
        // RFC 6238 appendix B (SHA-1), secret "12345678901234567890", truncated to 6 digits
        var secret = Totp.Base32Encode(Encoding.ASCII.GetBytes("12345678901234567890"));
        Assert.Equal("287082", Totp.Code(secret, 59 / 30));
        Assert.Equal("081804", Totp.Code(secret, 1111111109 / 30));
        Assert.Equal("050471", Totp.Code(secret, 1111111111 / 30));
        var now = DateTimeOffset.FromUnixTimeSeconds(59);
        var c = Totp.Verify(secret, "287082", now, null);
        Assert.Equal(1, c);
        Assert.Null(Totp.Verify(secret, "287082", now, c));          // replay of the same step
        Assert.Null(Totp.Verify(secret, "000000", now, null));
        Assert.Null(Totp.Verify(secret, "abc", now, null));
        Assert.Equal(Encoding.ASCII.GetBytes("12345678901234567890"), Totp.Base32Decode(secret));
    }

    [Fact]
    public void Login_throttle_locks_per_user_and_ip_and_resets()
    {
        var clock = new FakeClock();
        var t = new LoginThrottle(clock, Microsoft.Extensions.Options.Options.Create(new AuthOptions { MaxFailedAttempts = 3, LockoutMinutes = 15 }));
        for (var i = 0; i < 3; i++) t.Failure("alice", "1.1.1.1");
        Assert.True(t.IsLocked("alice", "1.1.1.1"));
        Assert.False(t.IsLocked("alice", "2.2.2.2"));      // an attacker elsewhere cannot lock the user out from other addresses
        Assert.False(t.IsLocked("bob", "1.1.1.1"));
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.False(t.IsLocked("alice", "1.1.1.1"));
        for (var i = 0; i < 3; i++) t.Failure("alice", "1.1.1.1");
        t.Reset("alice");
        Assert.False(t.IsLocked("alice", "1.1.1.1"));
    }

    [Fact]
    public void Account_delay_only_kicks_in_after_many_distributed_failures()
    {
        var clock = new FakeClock();
        var t = new LoginThrottle(clock, Microsoft.Extensions.Options.Options.Create(new AuthOptions()));
        for (var i = 0; i < 19; i++) t.Failure("alice", "10.0.0." + i);
        Assert.Equal(TimeSpan.Zero, t.AccountDelay("alice"));
        for (var i = 0; i < 5; i++) t.Failure("alice", "10.0.1." + i);
        Assert.True(t.AccountDelay("alice") > TimeSpan.Zero);
        Assert.False(t.IsLocked("alice", "10.9.9.9"), "delay, not a hard lock");
    }

    [Fact]
    public void Username_validation()
    {
        Assert.True(UserService.ValidUsername("alice.b-c_1"));
        Assert.False(UserService.ValidUsername("Al"));
        Assert.False(UserService.ValidUsername("UPPER"));
        Assert.False(UserService.ValidUsername("white space"));
    }

    private sealed class FakeClock : IClock
    {
        private DateTimeOffset _now = new(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);
        public DateTimeOffset UtcNow => _now;
        public void Advance(TimeSpan t) => _now += t;
    }
}
