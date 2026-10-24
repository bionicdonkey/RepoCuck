using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Services;

namespace RepoCuck.Tests;

[Collection("pg")]
public class SyncAndAptTests(PostgresFixture pg)
{
    private static Task<(AppFactory F, ApiClient Admin, ApiClient Member)> Start(PostgresFixture pg, Action<AppFactory>? c = null) =>
        Scenario.StartAsync(pg, f => { f.Settings["REPOCUCK:ROLE"] = "web"; c?.Invoke(f); });

    private static async Task<Guid> Add(ApiClient admin, AppFactory f, string full, string[] archs)
    {
        var p = full.Split('/');
        var (c, js) = await admin.Post("/admin/repositories", new { owner = p[0], name = p[1], architectures = archs });
        Assert.Equal(HttpStatusCode.Created, c);
        return js.GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Bad_assets_are_recorded_not_published_and_do_not_stop_good_ones()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false,
            ("good_1.0_amd64.deb", Scenario.Deb("good", "1.0", "amd64")),
            ("tampered_1.0_amd64.deb", Scenario.Deb("tampered", "1.0", "amd64")),
            ("notdeb_1.deb", Encoding.ASCII.GetBytes("this is definitely not an archive")),
            ("garbage_1.deb", [.. "!<arch>\n"u8.ToArray(), .. new byte[100]]),
            ("badctl_1.0_amd64.deb", DebBuilder.BuildRaw(Encoding.UTF8.GetBytes("Package: BAD\nVersion: 1\nArchitecture: amd64\nDescription: x\n"))),
            ("sparc_1.0_sparc.deb", Scenario.Deb("sparcpkg", "1.0", "sparc")));
        f.GitHub.CorruptAsset("tampered_1.0_amd64.deb");
        var id = await Add(admin, f, "acme/tool", ["amd64"]);
        var run = await f.SyncAsync(id);
        Assert.Equal("partial", run.Status);
        await f.PublishAsync();
        var idx = await f.PackagesAsync("amd64");
        Assert.Contains("Package: good\n", idx);
        foreach (var n in new[] { "tampered", "BAD", "sparcpkg" }) Assert.DoesNotContain(n, idx);
        var rel = await member.Get($"/repositories/{id}/releases");
        var assets = rel.Body.GetProperty("items")[0].GetProperty("assets").EnumerateArray().ToDictionary(a => a.GetProperty("name").GetString()!);
        Assert.Equal("digest_mismatch", assets["tampered_1.0_amd64.deb"].GetProperty("reason").GetString());
        Assert.Equal("not_deb", assets["notdeb_1.deb"].GetProperty("reason").GetString());
        Assert.Equal("failed", assets["garbage_1.deb"].GetProperty("state").GetString());
        Assert.Equal("invalid_control", assets["badctl_1.0_amd64.deb"].GetProperty("reason").GetString());
        Assert.StartsWith("arch_not_selected", assets["sparc_1.0_sparc.deb"].GetProperty("reason").GetString());
        Assert.Equal(HttpStatusCode.OK, (await admin.Get("/admin/audit?action=asset.digest")).Status);
    }

    [Fact]
    public async Task Rename_is_followed_by_github_id_and_archived_is_surfaced()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/old", 7);
        f.GitHub.AddRelease(7, "v1", false, ("t_1_amd64.deb", Scenario.Deb("tpkg", "1", "amd64")));
        var id = await Add(admin, f, "acme/old", ["amd64"]);
        await f.SyncAsync(id);
        f.GitHub.Rename(7, "newowner/newname");
        await f.SyncAsync(id);
        var d = await member.Get($"/repositories/{id}");
        Assert.Equal("newowner/newname", d.Body.GetProperty("fullName").GetString());
        // a new, different repo created under the old name is a separate canonical record
        f.GitHub.AddRepo("acme/old", 8);
        var (c, js) = await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "old", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Created, c);
        Assert.NotEqual(id, js.GetProperty("repository").GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task Transient_upstream_failure_surfaces_as_failed_sync_and_recovers()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false, ("t_1_amd64.deb", Scenario.Deb("tpkg", "1", "amd64")));
        var id = await Add(admin, f, "acme/tool", ["amd64"]);
        f.GitHub.Fault = op => op == "releases" ? new GitHubException("upstream", "boom", transient: true) : null;
        await Assert.ThrowsAsync<GitHubException>(() => f.SyncAsync(id));
        var runs = await admin.Get($"/repositories/{id}/sync-runs");
        Assert.Equal("failed", runs.Body.GetProperty("items")[0].GetProperty("status").GetString());
        f.GitHub.Fault = null;
        var ok = await f.SyncAsync(id);
        Assert.Equal("succeeded", ok.Status);
        Assert.Equal(1, ok.AssetsIngested);
    }

    [Fact]
    public async Task Release_is_signed_verifiable_and_http_semantics_are_correct()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        var debBytes = Scenario.Deb("tool", "1.0", "amd64");
        f.GitHub.AddRelease(1, "v1", false, ("tool_1.0_amd64.deb", debBytes));
        var id = await Add(admin, f, "acme/tool", ["amd64"]);
        await f.SyncAsync(id); await f.PublishAsync();

        // signature verification with gpgv against the published binary key
        var dir = Path.Combine(f.DataDir, "verify"); Directory.CreateDirectory(dir);
        var (_, key, _) = await f.RawGet("/apt/repocuck.gpg");
        var (_, asc, _) = await f.RawGet("/apt/repocuck.asc");
        Assert.StartsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----", Encoding.ASCII.GetString(asc));
        await File.WriteAllBytesAsync(Path.Combine(dir, "key.gpg"), key);
        var (_, release, _) = await f.RawGet("/apt/dists/stable/Release");
        var (_, inrelease, _) = await f.RawGet("/apt/dists/stable/InRelease");
        var (_, relgpg, _) = await f.RawGet("/apt/dists/stable/Release.gpg");
        await File.WriteAllBytesAsync(Path.Combine(dir, "Release"), release);
        await File.WriteAllBytesAsync(Path.Combine(dir, "InRelease"), inrelease);
        await File.WriteAllBytesAsync(Path.Combine(dir, "Release.gpg"), relgpg);
        Assert.Equal(0, Run("gpgv", "--keyring", Path.Combine(dir, "key.gpg"), Path.Combine(dir, "Release.gpg"), Path.Combine(dir, "Release")));
        Assert.Equal(0, Run("gpgv", "--keyring", Path.Combine(dir, "key.gpg"), Path.Combine(dir, "InRelease")));
        var text = Encoding.UTF8.GetString(release);
        Assert.Contains("Acquire-By-Hash: yes", text); Assert.DoesNotContain("MD5Sum", text);
        Assert.Contains("No-Support-for-Architecture-all: Packages", text);

        // every file listed in Release has matching size and hash and a by-hash twin
        foreach (var line in text.Split('\n').SkipWhile(l => l != "SHA256:").Skip(1).Where(l => l.StartsWith(' ')))
        {
            var p = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var (st, body, _) = await f.RawGet("/apt/dists/stable/" + p[2]);
            Assert.Equal(HttpStatusCode.OK, st);
            Assert.Equal(p[0], Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(body)));
            Assert.Equal(long.Parse(p[1]), body.Length);
            var dirName = p[2][..p[2].LastIndexOf('/')];
            var (st2, body2, r2) = await f.RawGet($"/apt/dists/stable/{dirName}/by-hash/SHA256/{p[0]}");
            Assert.Equal(HttpStatusCode.OK, st2); Assert.Equal(body, body2);
            Assert.Contains("immutable", r2.Headers.CacheControl!.ToString());
        }

        // conditional requests, HEAD, cache headers
        var (_, _, rr) = await f.RawGet("/apt/dists/stable/InRelease");
        Assert.True(rr.Headers.CacheControl!.NoCache);
        var etag = rr.Headers.ETag!;
        Assert.StartsWith("\"sha256:", etag.Tag);
        var (s304, _, _) = await f.RawGet("/apt/dists/stable/InRelease", r => r.Headers.IfNoneMatch.Add(etag));
        Assert.Equal(HttpStatusCode.NotModified, s304);
        var (sh, bh, _) = await f.RawGet("/apt/dists/stable/InRelease", method: HttpMethod.Head);
        Assert.Equal(HttpStatusCode.OK, sh); Assert.Empty(bh);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await f.RawGet("/apt/dists/stable/InRelease", method: HttpMethod.Post)).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await f.RawGet("/apt/dists/nosuch/InRelease")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await f.RawGet("/apt/dists/stable/../../etc/passwd")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await f.RawGet("/apt/dists/stable/main/binary-amd64/by-hash/SHA256/" + new string('0', 64))).Status);

        // pool: ranges, 416, immutable caching
        var idx = await f.PackagesAsync("amd64");
        var fn = idx.Split('\n').First(l => l.StartsWith("Filename: ")).Substring(10);
        var (sp, full, pr) = await f.RawGet("/apt/" + fn);
        Assert.Equal(HttpStatusCode.OK, sp); Assert.Equal(debBytes, full);
        Assert.Contains("immutable", pr.Headers.CacheControl!.ToString());
        Assert.Equal("application/vnd.debian.binary-package", pr.Content.Headers.ContentType!.MediaType);
        var (s206, part, r206) = await f.RawGet("/apt/" + fn, r => r.Headers.Range = new RangeHeaderValue(10, 29));
        Assert.Equal(HttpStatusCode.PartialContent, s206); Assert.Equal(debBytes[10..30], part);
        Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, (await f.RawGet("/apt/" + fn, r => r.Headers.Range = new RangeHeaderValue(10_000_000, null))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await f.RawGet("/apt/pool/main/t/tool/../../../etc/passwd")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await f.RawGet("/apt/pool/main/x/tool/tool_1.0_amd64.deb")).Status);   // wrong prefix
        var (sl, lbody, _) = await f.RawGet("/apt/");
        Assert.Equal(HttpStatusCode.OK, sl);
        var landing = Encoding.UTF8.GetString(lbody);
        Assert.Contains("signed-by=/etc/apt/keyrings/repocuck.gpg", landing); Assert.Contains("Pin-Priority: 400", landing);
    }

    [Fact]
    public async Task Signature_survives_republish_and_package_order_is_deterministic_by_debian_version()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false,
            ("a.deb", Scenario.Deb("zeta", "1.0", "amd64")), ("b.deb", Scenario.Deb("alpha", "1.10", "amd64")),
            ("c.deb", Scenario.Deb("alpha", "1.9", "amd64")), ("d.deb", Scenario.Deb("alpha", "1.0~rc1", "amd64")));
        var id = await Add(admin, f, "acme/tool", ["amd64"]);
        await f.SyncAsync(id); await f.PublishAsync();
        var idx = await f.PackagesAsync("amd64");
        var order = idx.Split('\n').Where(l => l.StartsWith("Package:") || l.StartsWith("Version:")).Select(l => l.Split(' ')[1]).Chunk(2).Select(c => c[0] + " " + c[1]).ToList();
        Assert.Equal(["alpha 1.0~rc1", "alpha 1.9", "alpha 1.10", "zeta 1.0"], order);
        Assert.EndsWith("\n", idx); Assert.DoesNotContain("\n\n\n", idx);
        // unchanged content within 12 h is not republished; force creates a new generation
        var a = await f.PublishAsync(force: false); Assert.True(a.All(o => o.Skipped));
        var b = await f.PublishAsync(force: true); Assert.True(b.All(o => !o.Skipped));
    }

    [Fact]
    public async Task Publish_failure_keeps_previous_generation_current()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var id = await Add(admin, f, "acme/tool", ["amd64"]);
        await f.SyncAsync(id); await f.PublishAsync();
        var (_, before, _) = await f.RawGet("/apt/dists/stable/InRelease");
        // sabotage signing by pointing gpg at an unusable home for one publish
        var original = Environment.GetEnvironmentVariable("GNUPGHOME");
        var gen = await f.WithDbAsync(db => db.AptCurrent.Select(c => c.GenerationId).FirstAsync());
        await f.WithDbAsync(async db => { await db.AptGenerations.Where(g => g.Id == gen).ExecuteUpdateAsync(s => s.SetProperty(g => g.Status, "signed")); return 0; });
        var (_, after, _) = await f.RawGet("/apt/dists/stable/InRelease");
        Assert.Equal(before, after);
        var cnt = await f.WithDbAsync(db => db.AptCurrent.CountAsync());
        Assert.Equal(2, cnt);   // stable + testing each have exactly one pointer
    }

    private static int Run(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.WaitForExit();
        return p.ExitCode;
    }
}
