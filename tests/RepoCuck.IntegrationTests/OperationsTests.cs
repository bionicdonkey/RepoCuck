using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Infrastructure.Signing;

namespace RepoCuck.Tests;

public sealed class ToggleSigner(GpgSigner inner) : ISigner
{
    public static volatile bool Fail;
    public string Fingerprint => inner.Fingerprint;
    public IReadOnlyList<string> ActiveFingerprints => inner.ActiveFingerprints;
    public Task<IReadOnlyList<SigningKeyInfo>> ListKeysAsync(CancellationToken ct) => inner.ListKeysAsync(ct);
    public Task<string> StartRotationAsync(CancellationToken ct) => inner.StartRotationAsync(ct);
    public Task CompleteRotationAsync(CancellationToken ct) => inner.CompleteRotationAsync(ct);
    public Task EnsureReadyAsync(CancellationToken ct) => inner.EnsureReadyAsync(ct);
    public Task<SigningResult> SignAsync(byte[] release, CancellationToken ct) => Fail ? throw new InvalidOperationException("signing unavailable") : inner.SignAsync(release, ct);
    public Task<byte[]> ExportPublicKeyAsync(CancellationToken ct) => inner.ExportPublicKeyAsync(ct);
    public Task<byte[]> ExportPublicKeyArmoredAsync(CancellationToken ct) => inner.ExportPublicKeyArmoredAsync(ct);
    public Task<DateTimeOffset?> GetKeyExpiryAsync(CancellationToken ct) => inner.GetKeyExpiryAsync(ct);
}

[Collection("pg")]
public class OperationsTests(PostgresFixture pg)
{
    private static Task<(AppFactory F, ApiClient Admin, ApiClient Member)> Start(PostgresFixture pg, Action<AppFactory>? c = null) =>
        Scenario.StartAsync(pg, f => { f.Settings["REPOCUCK:ROLE"] = "web"; c?.Invoke(f); });

    [Fact]
    public async Task Failed_signing_keeps_previous_generation_current_and_marks_new_one_failed()
    {
        var (f, admin, _) = await Start(pg, x => x.ExtraServices = s =>
        {
            s.RemoveAll<ISigner>(); s.AddSingleton<GpgSigner>(); s.AddSingleton<ISigner>(sp => new ToggleSigner(sp.GetRequiredService<GpgSigner>()));
        });
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        await f.SyncAsync(js.GetProperty("id").GetGuid()); await f.PublishAsync();
        var (_, before, _) = await f.RawGet("/apt/dists/stable/InRelease");
        f.GitHub.AddRelease(1, "v2", false, ("b.deb", Scenario.Deb("tool", "2.0", "amd64")));
        await f.SyncAsync(js.GetProperty("id").GetGuid());
        ToggleSigner.Fail = true;
        try { await Assert.ThrowsAsync<InvalidOperationException>(() => f.PublishAsync()); }
        finally { ToggleSigner.Fail = false; }
        var (st, after, _) = await f.RawGet("/apt/dists/stable/InRelease");
        Assert.Equal(HttpStatusCode.OK, st); Assert.Equal(before, after);                       // clients still see the old signed index
        Assert.DoesNotContain("2.0", await f.PackagesAsync("amd64"));
        var failed = await f.WithDbAsync(db => db.AptGenerations.CountAsync(g => g.Status == "failed"));
        Assert.True(failed >= 1);
        await f.PublishAsync();                                                                  // recovers on the next run
        Assert.Contains("Version: 2.0", await f.PackagesAsync("amd64"));
    }

    [Fact]
    public async Task Retention_keeps_newest_versions_and_reclaims_everything_after_the_grace_period()
    {
        var (f, admin, _) = await Start(pg, x => { x.UseFakeClock = true; x.Settings["Retention:VersionsPerPackage"] = "2"; });
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")), ("b.deb", Scenario.Deb("tool", "1.1", "amd64")),
            ("c.deb", Scenario.Deb("tool", "1.2", "amd64")), ("d.deb", Scenario.Deb("tool", "1.10", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        var id = js.GetProperty("id").GetGuid();
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.Equal(4, (await f.PackagesAsync("amd64")).Split("Package: tool\n").Length - 1);

        await f.WithServiceAsync<RetentionService, int>(async r => { await r.SweepAsync(default); return 0; });
        await f.PublishAsync();
        var idx = await f.PackagesAsync("amd64");
        Assert.Equal(2, idx.Split("Package: tool\n").Length - 1);
        Assert.Contains("Version: 1.10", idx); Assert.Contains("Version: 1.2\n", idx);          // Debian ordering: 1.10 > 1.2 > 1.1 > 1.0
        Assert.DoesNotContain("Version: 1.0\n", idx); Assert.DoesNotContain("Version: 1.1\n", idx);

        // tombstones are removed (with their blobs) only after the retained generations age out
        var blobsBefore = await f.WithDbAsync(db => db.Blobs.CountAsync(b => !b.IsIndex));
        Assert.Equal(4, blobsBefore);
        f.Clock.Advance(TimeSpan.FromHours(60));
        await f.WithServiceAsync<RetentionService, int>(async r => { await r.SweepAsync(default); return 0; });
        Assert.Equal(2, await f.WithDbAsync(db => db.PackageVariants.CountAsync()));
        Assert.Equal(2, await f.WithDbAsync(db => db.Blobs.CountAsync(b => !b.IsIndex)));
        // dropped versions are never re-ingested
        var run = await f.SyncAsync(id);
        Assert.Equal(0, run.VariantsCreated);
        Assert.Equal(2, await f.WithDbAsync(db => db.PackageVariants.CountAsync()));
    }

    [Fact]
    public async Task Old_generations_are_deleted_only_beyond_both_count_and_age()
    {
        var (f, admin, _) = await Start(pg, x => { x.UseFakeClock = true; });
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        await f.SyncAsync(js.GetProperty("id").GetGuid());
        for (var i = 0; i < 8; i++) { await f.PublishAsync(); f.Clock.Advance(TimeSpan.FromMinutes(1)); }
        Assert.True(await f.WithDbAsync(db => db.AptGenerations.CountAsync()) >= 14);          // stable+testing
        await f.WithServiceAsync<RetentionService, int>(async r => { await r.SweepAsync(default); return 0; });
        Assert.True(await f.WithDbAsync(db => db.AptGenerations.CountAsync()) >= 14, "recent generations are kept even beyond the count");
        f.Clock.Advance(TimeSpan.FromHours(72));
        await f.WithServiceAsync<RetentionService, int>(async r => { await r.SweepAsync(default); return 0; });
        var perSuite = await f.WithDbAsync(db => db.AptGenerations.GroupBy(g => g.SuiteId).Select(g => g.Count()).ToListAsync());
        Assert.All(perSuite, n => Assert.Equal(5, n));                                          // count floor
        var (st, _, _) = await f.RawGet("/apt/dists/stable/InRelease");
        Assert.Equal(HttpStatusCode.OK, st);                                                    // current one survives
    }

    [Fact]
    public async Task Unblocked_repository_revives_tombstoned_packages()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        var id = js.GetProperty("id").GetGuid();
        await f.SyncAsync(id); await f.PublishAsync();
        await admin.Post($"/admin/repositories/{id}/block", new { reason = "x" }); await f.PublishAsync();
        Assert.DoesNotContain("tool", await f.PackagesAsync("amd64"));
        await admin.Post($"/admin/repositories/{id}/unblock");
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{id}/activate")).Status);
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));
    }

    [Fact]
    public async Task Admin_delete_removes_variant_from_index_and_it_is_not_reingested()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")), ("b.deb", Scenario.Deb("keep", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        var id = js.GetProperty("id").GetGuid();
        await f.SyncAsync(id); await f.PublishAsync();
        var vid = await f.WithDbAsync(db => db.PackageVariants.Where(v => v.Version == "1.0").Join(db.Packages, v => v.PackageId, p => p.Id, (v, p) => new { v.Id, p.Name }).Where(x => x.Name == "tool").Select(x => x.Id).FirstAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Delete($"/admin/variants/{vid}")).Status);
        await f.PublishAsync();
        var idx = await f.PackagesAsync("amd64");
        Assert.DoesNotContain("Package: tool\n", idx); Assert.Contains("Package: keep\n", idx);
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.DoesNotContain("Package: tool\n", await f.PackagesAsync("amd64"));
    }

    [Fact]
    public async Task Background_pipeline_syncs_and_publishes_without_manual_calls()
    {
        var (f, admin, member) = await Scenario.StartAsync(pg);   // ROLE=all: job runner + scheduler are running
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (c, js) = await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Created, c);
        var repoId = js.GetProperty("repository").GetProperty("id").GetGuid();
        // quarantine sync runs in the background
        var quarantined = await AppFactory.PollAsync(async () => (await member.Get($"/repositories/{repoId}/packages")).Body.GetProperty("items").GetArrayLength() == 1 ? "x" : null);
        Assert.NotNull(quarantined);
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/requests/{js.GetProperty("request").GetProperty("id").GetGuid()}/approve", new { })).Status);
        var published = await AppFactory.PollAsync(async () => (await f.PackagesAsync("amd64")).Contains("Package: tool\n") ? "x" : null, 90);
        Assert.NotNull(published);
        // new upstream release is picked up by the scheduler after next_sync_at passes
        f.GitHub.AddRelease(1, "v2", false, ("b.deb", Scenario.Deb("tool", "2.0", "amd64")));
        await f.WithDbAsync(async db => { await db.Repositories.ExecuteUpdateAsync(s => s.SetProperty(r => r.NextSyncAt, DateTimeOffset.UtcNow.AddSeconds(-1))); return 0; });
        var upgraded = await AppFactory.PollAsync(async () => (await f.PackagesAsync("amd64")).Contains("Version: 2.0") ? "x" : null, 90);
        Assert.NotNull(upgraded);
        var jobs = await admin.Get("/admin/jobs?state=dead");
        Assert.Empty(jobs.Body.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Concurrent_syncs_of_the_same_repository_do_not_duplicate_packages()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")), ("b.deb", Scenario.Deb("other", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        var id = js.GetProperty("id").GetGuid();
        var results = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => f.SyncAsync(id).ContinueWith(t => t.IsCompletedSuccessfully)));
        await f.PublishAsync();
        var idx = await f.PackagesAsync("amd64");
        Assert.Equal(1, idx.Split("Package: tool\n").Length - 1);
        Assert.Equal(2, await f.WithDbAsync(db => db.PackageVariants.CountAsync()));
    }
}

[Collection("pg")]
public class SigningRotationTests(PostgresFixture pg)
{
    /// <summary>apt's rule: at least one good signature from a trusted key and no bad ones (signatures by unknown keys are ignored).</summary>
    private static int Gpgv(string keyring, string dir, params string[] files)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("gpgv") { RedirectStandardError = true, RedirectStandardOutput = true };
        psi.ArgumentList.Add("--status-fd"); psi.ArgumentList.Add("1");
        psi.ArgumentList.Add("--keyring"); psi.ArgumentList.Add(Path.Combine(dir, keyring));
        foreach (var f in files) psi.ArgumentList.Add(Path.Combine(dir, f));
        using var p = System.Diagnostics.Process.Start(psi)!;
        var status = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return status.Contains("] VALIDSIG ") && !status.Contains("] BADSIG ") ? 0 : 1;
    }

    [Fact]
    public async Task Rotation_with_overlap_never_breaks_verification_for_old_or_updated_clients()
    {
        var (f, admin, _) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        await f.SyncAsync(js.GetProperty("id").GetGuid()); await f.PublishAsync();
        var dir = Path.Combine(f.DataDir, "rot"); Directory.CreateDirectory(dir);

        async Task Snapshot(string keyFile)
        {
            await File.WriteAllBytesAsync(Path.Combine(dir, keyFile), (await f.RawGet("/apt/repocuck.gpg")).Body);
            await File.WriteAllBytesAsync(Path.Combine(dir, "Release"), (await f.RawGet("/apt/dists/stable/Release")).Body);
            await File.WriteAllBytesAsync(Path.Combine(dir, "InRelease"), (await f.RawGet("/apt/dists/stable/InRelease")).Body);
            await File.WriteAllBytesAsync(Path.Combine(dir, "Release.gpg"), (await f.RawGet("/apt/dists/stable/Release.gpg")).Body);
        }

        await Snapshot("old.gpg");
        Assert.Equal(0, Gpgv("old.gpg", dir, "InRelease"));
        var before = (await admin.Get("/admin/signing")).Body;
        var oldFpr = before.GetProperty("fingerprint").GetString();
        Assert.False(before.GetProperty("rotationInProgress").GetBoolean());

        Assert.Equal(HttpStatusCode.Conflict, (await admin.Post("/admin/signing/rotate", new { action = "complete" })).Status);
        Assert.Equal(HttpStatusCode.OK, (await admin.Post("/admin/signing/rotate", new { action = "start" })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.Post("/admin/signing/rotate", new { action = "start" })).Status);
        await f.PublishAsync();
        await Snapshot("both.gpg");
        Assert.Equal(0, Gpgv("old.gpg", dir, "InRelease"));             // clients that still only trust the old key keep working
        Assert.Equal(0, Gpgv("old.gpg", dir, "Release.gpg", "Release"));
        Assert.Equal(0, Gpgv("both.gpg", dir, "InRelease"));            // clients that picked up the new keyring work too
        Assert.Equal(0, Gpgv("both.gpg", dir, "Release.gpg", "Release"));
        var during = (await admin.Get("/admin/signing")).Body;
        Assert.True(during.GetProperty("rotationInProgress").GetBoolean());
        Assert.Equal(2, during.GetProperty("keys").GetArrayLength());

        Assert.Equal(HttpStatusCode.OK, (await admin.Post("/admin/signing/rotate", new { action = "complete" })).Status);
        await f.PublishAsync();
        await Snapshot("new.gpg");
        Assert.Equal(0, Gpgv("new.gpg", dir, "InRelease"));
        Assert.Equal(0, Gpgv("new.gpg", dir, "Release.gpg", "Release"));
        Assert.NotEqual(0, Gpgv("old.gpg", dir, "InRelease"));          // the old key no longer vouches for new indices
        var after = (await admin.Get("/admin/signing")).Body;
        Assert.NotEqual(oldFpr, after.GetProperty("fingerprint").GetString());
        Assert.False(after.GetProperty("rotationInProgress").GetBoolean());
    }
}

[Collection("pg")]
public class CliTests(PostgresFixture pg)
{
    [Fact]
    public async Task Offline_cli_lists_resets_promotes_and_migrates()
    {
        var (f, admin, member) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        var cfg = new Dictionary<string, string?> { ["ConnectionStrings:Postgres"] = f.ConnectionString, ["Storage:Root"] = f.DataDir };
        async Task<(int Code, string Out)> Run(params string[] args)
        {
            var w = new StringWriter();
            var code = await Web.Cli.RunAsync(args, cfg, w);
            return (code, w.ToString());
        }
        var list = await Run("admin", "list");
        Assert.Equal(0, list.Code); Assert.Contains("alice", list.Out); Assert.Contains("admin", list.Out);

        var reset = await Run("admin", "reset", "--username", "alice");
        Assert.Equal(0, reset.Code);
        var temp = System.Text.RegularExpressions.Regex.Match(reset.Out, "password for alice: (\\S+)").Groups[1].Value;
        Assert.NotEmpty(temp);
        Assert.False(await f.NewClient().LoginAsync("alice", "alice-new-pass-1234"), "old password no longer works");
        var fresh = f.NewClient();
        Assert.True(await fresh.LoginAsync("alice", temp));
        Assert.Equal("password_change_required", (await fresh.Get("/repositories")).Body.GetProperty("code").GetString());   // forced change

        Assert.Equal(1, (await Run("admin", "reset", "--username", "nobody")).Code);
        Assert.Equal(2, (await Run("admin", "reset")).Code);
        Assert.Equal(0, (await Run("admin", "promote", "--username", "alice")).Code);
        var promoted = f.NewClient(); Assert.True(await promoted.LoginAsync("alice", temp));
        await promoted.Post("/me/password", new { current = temp, newPassword = "alice-after-reset-99" });
        promoted = f.NewClient(); Assert.True(await promoted.LoginAsync("alice", "alice-after-reset-99"));
        Assert.Equal("admin", (await promoted.Get("/me")).Body.GetProperty("role").GetString());
        Assert.Equal(0, (await Run("--migrate")).Code);   // idempotent
    }
}

[Collection("pg")]
public class SigningKeyImportTests(PostgresFixture pg)
{
    private static (string Fpr, string KeyFile, string PassFile, string Dir) MakeKey(string pass)
    {
        var dir = Path.Combine(Path.GetTempPath(), "rc-key-" + Guid.NewGuid().ToString("N"));
        var home = Path.Combine(dir, "home"); Directory.CreateDirectory(home);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(home, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string Run(params string[] args)
        {
            var psi = new System.Diagnostics.ProcessStartInfo("gpg") { RedirectStandardOutput = true, RedirectStandardError = true };
            psi.Environment["GNUPGHOME"] = home;
            foreach (var a in new[] { "--batch", "--no-tty", "--yes", "--pinentry-mode", "loopback", "--passphrase", pass }.Concat(args)) psi.ArgumentList.Add(a);
            using var p = System.Diagnostics.Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEnd(); p.WaitForExit();
            Assert.Equal(0, p.ExitCode);
            return o;
        }
        Run("--quick-gen-key", "Imported Key <imported@example.com>", "ed25519", "sign", "5y");
        var fpr = Run("--list-secret-keys", "--with-colons").Split('\n').First(l => l.StartsWith("fpr:")).Split(':')[9];
        var keyFile = Path.Combine(dir, "signing.key");
        File.WriteAllText(keyFile, Run("--armor", "--export-secret-keys", fpr));
        var passFile = Path.Combine(dir, "pass"); File.WriteAllText(passFile, pass + "\n");
        return (fpr, keyFile, passFile, dir);
    }

    [Fact]
    public async Task Imported_passphrase_protected_key_signs_the_repository_and_the_fingerprint_pin_is_enforced()
    {
        var (fpr, keyFile, passFile, dir) = MakeKey("correct horse battery");
        try
        {
            var (f, admin, _) = await Scenario.StartAsync(pg, x =>
            {
                x.Settings["REPOCUCK:ROLE"] = "web"; x.Settings["Apt:SigningKeyPath"] = keyFile; x.Settings["Apt:SigningKeyPassphraseFile"] = passFile; x.Settings["Apt:KeyFingerprint"] = fpr;
            });
            using var _ = f;
            f.GitHub.AddRepo("acme/tool", 1);
            f.GitHub.AddRelease(1, "v", false, ("a.deb", Scenario.Deb("tool", "1.0", "amd64")));
            var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
            await f.SyncAsync(js.GetProperty("id").GetGuid()); await f.PublishAsync();
            Assert.Equal(fpr, (await admin.Get("/admin/signing")).Body.GetProperty("fingerprint").GetString());
            var vdir = Path.Combine(dir, "verify"); Directory.CreateDirectory(vdir);
            await File.WriteAllBytesAsync(Path.Combine(vdir, "k.gpg"), (await f.RawGet("/apt/repocuck.gpg")).Body);
            await File.WriteAllBytesAsync(Path.Combine(vdir, "InRelease"), (await f.RawGet("/apt/dists/stable/InRelease")).Body);
            var psi = new System.Diagnostics.ProcessStartInfo("gpgv") { RedirectStandardError = true, RedirectStandardOutput = true };
            foreach (var a in new[] { "--status-fd", "1", "--keyring", Path.Combine(vdir, "k.gpg"), Path.Combine(vdir, "InRelease") }) psi.ArgumentList.Add(a);
            using var p = System.Diagnostics.Process.Start(psi)!;
            var status = p.StandardOutput.ReadToEnd(); p.WaitForExit();
            Assert.Contains("VALIDSIG " + fpr, status);                                           // signed by exactly the imported key

            // wrong pin -> refuse to start; wrong passphrase -> refuse to start
            using var badPin = new AppFactory { ConnectionString = await pg.CreateDatabaseAsync() };
            badPin.Settings["REPOCUCK:ROLE"] = "all"; badPin.Settings["Apt:SigningKeyPath"] = keyFile; badPin.Settings["Apt:SigningKeyPassphraseFile"] = passFile;
            badPin.Settings["Apt:KeyFingerprint"] = new string('A', 40);
            Assert.ThrowsAny<Exception>(() => badPin.CreateClient());
            var wrongPass = Path.Combine(dir, "wrong"); File.WriteAllText(wrongPass, "nope");
            using var badPass = new AppFactory { ConnectionString = await pg.CreateDatabaseAsync() };
            badPass.Settings["REPOCUCK:ROLE"] = "all"; badPass.Settings["Apt:SigningKeyPath"] = keyFile; badPass.Settings["Apt:SigningKeyPassphraseFile"] = wrongPass;
            Assert.ThrowsAny<Exception>(() => badPass.CreateClient());
        }
        finally { try { Directory.Delete(dir, true); } catch { /* ignore */ } }
    }
}
