using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Infrastructure.Data;
using Testcontainers.PostgreSql;

namespace RepoCuck.Tests;

/// <summary>One Postgres container shared by all integration tests; each factory gets its own database.</summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _pg = new PostgreSqlBuilder("postgres:17-alpine").Build();
    private int _n;

    public Task InitializeAsync() => _pg.StartAsync();
    public Task DisposeAsync() => _pg.DisposeAsync().AsTask();

    public async Task<string> CreateDatabaseAsync()
    {
        var name = $"rc_{Interlocked.Increment(ref _n)}_{Guid.NewGuid():N}"[..30];
        await using var c = new NpgsqlConnection(_pg.GetConnectionString());
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand($"create database {name}", c);
        await cmd.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(_pg.GetConnectionString()) { Database = name, Pooling = true, MaxPoolSize = 20 }.ConnectionString;
    }
}

[CollectionDefinition("pg")]
public class PgCollection : ICollectionFixture<PostgresFixture>;

public sealed class FakeClock : IClock
{
    private DateTimeOffset _now = DateTimeOffset.UtcNow;
    public DateTimeOffset UtcNow => _now;
    public void Advance(TimeSpan t) => _now += t;
}

public sealed record FakeAsset(long Id, string Name, byte[] Data, string? Digest = null, bool Corrupt = false);
public sealed record FakeRelease(long Id, string Tag, bool Prerelease, params FakeAsset[] Assets);

public sealed class FakeGitHub : IGitHubClient
{
    private readonly ConcurrentDictionary<long, (GhRepo Repo, List<FakeRelease> Releases)> _repos = new();
    private long _assetSeq = 1_000_000;
    public int RateLimitRemainingPercent => 100;
    public Func<string, Exception?>? Fault { get; set; }

    public long NextAssetId() => Interlocked.Increment(ref _assetSeq);

    public GhRepo AddRepo(string full, long id, bool archived = false)
    {
        var parts = full.Split('/');
        var r = new GhRepo(id, parts[0], parts[1], full, $"https://github.com/{full}", $"fixture {full}", "MIT", "main", archived, false);
        _repos[id] = (r, new List<FakeRelease>());
        return r;
    }

    public void Rename(long id, string newFull)
    {
        var (r, rel) = _repos[id];
        var p = newFull.Split('/');
        _repos[id] = (r with { Owner = p[0], Name = p[1], FullName = newFull, HtmlUrl = "https://github.com/" + newFull }, rel);
    }

    public void AddRelease(long repoId, string tag, bool prerelease, params (string Name, byte[] Data)[] assets)
    {
        var rel = new FakeRelease(_repos[repoId].Releases.Count + 1 + repoId * 100, tag, prerelease,
            assets.Select(a => new FakeAsset(NextAssetId(), a.Name, a.Data)).ToArray());
        _repos[repoId].Releases.Insert(0, rel);
    }

    public void SetPrerelease(long repoId, string tag, bool value)
    {
        var list = _repos[repoId].Releases;
        var i = list.FindIndex(r => r.Tag == tag);
        list[i] = list[i] with { Prerelease = value };
    }

    public void CorruptAsset(string name)
    {
        foreach (var (_, rels) in _repos.Values)
            for (var i = 0; i < rels.Count; i++)
                rels[i] = rels[i] with { Assets = rels[i].Assets.Select(a => a.Name == name ? a with { Corrupt = true } : a).ToArray() };
    }

    public Task<GhRepo> GetRepoAsync(string owner, string name, CancellationToken ct)
    {
        if (Fault?.Invoke("repo") is { } f0) throw f0;
        var hit = _repos.Values.FirstOrDefault(r => string.Equals(r.Repo.FullName, $"{owner}/{name}", StringComparison.OrdinalIgnoreCase));
        return hit.Repo is null ? throw new GitHubException("not_found", "not found") : Task.FromResult(hit.Repo);
    }

    public Task<GhRepo> GetRepoByIdAsync(long id, CancellationToken ct)
    {
        if (Fault?.Invoke("repo") is { } f) throw f;
        return _repos.TryGetValue(id, out var h) ? Task.FromResult(h.Repo) : throw new GitHubException("not_found", "not found");
    }

    public Task<IReadOnlyList<GhRelease>> GetReleasesAsync(string owner, string name, int max, CancellationToken ct)
    {
        if (Fault?.Invoke("releases") is { } f) throw f;
        var hit = _repos.Values.First(r => string.Equals(r.Repo.FullName, $"{owner}/{name}", StringComparison.OrdinalIgnoreCase));
        IReadOnlyList<GhRelease> list = hit.Releases.Take(max).Select(r => new GhRelease(r.Id, r.Tag, r.Tag, "", r.Prerelease, false, DateTimeOffset.UtcNow, null,
            r.Assets.Select(a => new GhAsset(a.Id, a.Name, a.Data.Length, "application/octet-stream",
                a.Corrupt ? new string('0', 64) : Convert.ToHexStringLower(SHA256.HashData(a.Data)), 0, "fake://" + a.Id)).ToList())).ToList();
        return Task.FromResult(list);
    }

    public async Task<DownloadResult> DownloadAssetAsync(GhAsset asset, long maxBytes, string tempDir, CancellationToken ct)
    {
        var id = long.Parse(asset.Url["fake://".Length..]);
        var data = _repos.Values.SelectMany(r => r.Releases).SelectMany(r => r.Assets).First(a => a.Id == id).Data;
        if (data.Length > maxBytes) throw new GitHubException("too_large", "too large");
        Directory.CreateDirectory(tempDir);
        var path = Path.Combine(tempDir, Guid.NewGuid().ToString("N") + ".part");
        await File.WriteAllBytesAsync(path, data, ct);
        return new DownloadResult(path, data.Length, Convert.ToHexStringLower(SHA256.HashData(data)), Convert.ToHexStringLower(SHA512.HashData(data)));
    }
}

public sealed class PeerFilter(string ip) : Microsoft.AspNetCore.Hosting.IStartupFilter
{
    public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) => app =>
    {
        Microsoft.AspNetCore.Builder.UseExtensions.Use(app, async (Microsoft.AspNetCore.Http.HttpContext ctx, Func<Task> n) => { ctx.Connection.RemoteIpAddress ??= IPAddress.Parse(ip); await n(); });
        next(app);
    };
}

public class AppFactory : WebApplicationFactory<Program>
{
    public FakeGitHub GitHub { get; } = new();
    public FakeClock Clock { get; } = new();
    public string DataDir { get; } = Path.Combine(Path.GetTempPath(), "rc-it-" + Guid.NewGuid().ToString("N"));
    public Dictionary<string, string?> Settings { get; } = new();
    public string ConnectionString { get; set; } = "";
    public bool UseFakeClock { get; set; }
    public Action<IServiceCollection>? ExtraServices { get; set; }
    public string? PeerAddress { get; set; }

    protected override void ConfigureWebHost(IWebHostBuilder b)
    {
        Environment.SetEnvironmentVariable("GNUPGHOME", null);
        b.UseEnvironment("Production");
        var s = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Postgres"] = ConnectionString,
            ["Storage:Root"] = DataDir,
            ["Security:PublicScheme"] = "http",
            ["REPOCUCK:BASE_URL"] = "http://localhost",
            ["Bootstrap:AdminUsername"] = "admin",
            ["Bootstrap:AdminPasswordFile"] = WritePasswordFile(),
            ["Limits:LoginAttemptsPer5MinutesPerIp"] = "1000",
            ["Limits:RequestsPerHour"] = "1000",
            ["Limits:PendingRequestsPerUser"] = "50",
            ["Apt:EnableTesting"] = "true",
            ["Jobs:WorkerConcurrency"] = "2",
            ["Logging:LogLevel:Default"] = "Warning",
        };
        foreach (var (k, v) in Settings) s[k] = v;
        foreach (var (k, v) in s) b.UseSetting(k, v);
        b.ConfigureServices(services =>
        {
            services.RemoveAll<IGitHubClient>();
            services.AddSingleton<IGitHubClient>(GitHub);
            if (UseFakeClock) { services.RemoveAll<IClock>(); services.AddSingleton<IClock>(Clock); }
            ExtraServices?.Invoke(services);
            if (PeerAddress is not null) services.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter>(_ => new PeerFilter(PeerAddress));
        });
    }

    private string WritePasswordFile()
    {
        Directory.CreateDirectory(DataDir);
        var p = Path.Combine(DataDir, "admin_pw");
        File.WriteAllText(p, "integration-admin-pass-1");
        return p;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(DataDir, true); } catch { /* ignore */ }
    }

    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> f)
    {
        await using var scope = Services.CreateAsyncScope();
        var db = await scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContextAsync();
        await using (db) return await f(db);
    }

    public async Task<T> WithServiceAsync<TS, T>(Func<TS, Task<T>> f) where TS : notnull
    {
        await using var scope = Services.CreateAsyncScope();
        return await f(scope.ServiceProvider.GetRequiredService<TS>());
    }

    public ApiClient NewClient() => new(this);

    public Task<Domain.SyncRun> SyncAsync(Guid repoId, string trigger = "manual", bool reeval = false) =>
        WithServiceAsync<Infrastructure.Services.SyncService, Domain.SyncRun>(s => s.SyncAsync(repoId, trigger, reeval, default));

    public Task<IReadOnlyList<Infrastructure.Services.PublishOutcome>> PublishAsync(bool force = true) =>
        WithServiceAsync<Infrastructure.Services.PublisherService, IReadOnlyList<Infrastructure.Services.PublishOutcome>>(p => p.PublishAsync(null, force, default));

    private HttpClient? _anon;
    public async Task<(HttpStatusCode Status, byte[] Body, HttpResponseMessage Resp)> RawGet(string path, Action<HttpRequestMessage>? tweak = null, HttpMethod? method = null)
    {
        _anon ??= CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var req = new HttpRequestMessage(method ?? HttpMethod.Get, path);
        tweak?.Invoke(req);
        var resp = await _anon.SendAsync(req);
        return (resp.StatusCode, await resp.Content.ReadAsByteArrayAsync(), resp);
    }

    public async Task<string> PackagesAsync(string arch, string suite = "stable")
    {
        var (st, body, _) = await RawGet($"/apt/dists/{suite}/main/binary-{arch}/Packages");
        return st == HttpStatusCode.OK ? System.Text.Encoding.UTF8.GetString(body) : "";
    }

    /// <summary>Files an add_repo request, syncs it in quarantine and (optionally) approves it, then syncs and publishes.</summary>
    public async Task<Guid> AddApprovedRepoAsync(ApiClient member, ApiClient admin, string full, string[] archs, bool publish = true)
    {
        var (c, js) = await member.Post("/requests", new { kind = "add_repo", url = "https://github.com/" + full, architectures = archs });
        Assert.Equal(HttpStatusCode.Created, c);
        var repoId = js.GetProperty("repository").GetProperty("id").GetGuid();
        await SyncAsync(repoId, "quarantine");
        var (c2, _) = await admin.Post($"/admin/requests/{js.GetProperty("request").GetProperty("id").GetGuid()}/approve", new { });
        Assert.Equal(HttpStatusCode.OK, c2);
        if (publish) { await SyncAsync(repoId); await PublishAsync(); }
        return repoId;
    }

    public static async Task<T?> PollAsync<T>(Func<Task<T?>> f, int seconds = 60) where T : class
    {
        var end = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < end)
        {
            var r = await f();
            if (r is not null) return r;
            await Task.Delay(300);
        }
        return null;
    }
}

public sealed class ApiClient
{
    public HttpClient Http { get; }
    private string? _csrf;
    public ApiClient(AppFactory f) => Http = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });

    public async Task<bool> LoginAsync(string user, string pw)
    {
        var page = await Http.GetStringAsync("/login");
        var tok = Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var resp = await Http.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["Username"] = user, ["Password"] = pw, ["__RequestVerificationToken"] = tok }));
        _csrf = null;
        return resp.StatusCode == HttpStatusCode.Redirect && resp.Headers.Location?.OriginalString.Contains("/login") != true;
    }

    public async Task<(HttpStatusCode Status, JsonElement Body)> SendAsync(HttpMethod m, string path, object? body = null, bool csrf = true)
    {
        var req = new HttpRequestMessage(m, "/api/v1" + path);
        if (m != HttpMethod.Get && csrf)
        {
            _csrf ??= (await (await Http.GetAsync("/api/v1/csrf")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString();
            req.Headers.Add("X-Repocuck-CSRF", _csrf);
        }
        if (body is not null) req.Content = JsonContent.Create(body);
        else if (m != HttpMethod.Get) req.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        var resp = await Http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        JsonElement js = default;
        if (!string.IsNullOrWhiteSpace(text)) try { js = JsonDocument.Parse(text).RootElement.Clone(); } catch { /* not json */ }
        return (resp.StatusCode, js);
    }

    public Task<(HttpStatusCode Status, JsonElement Body)> Get(string p) => SendAsync(HttpMethod.Get, p);
    public Task<(HttpStatusCode Status, JsonElement Body)> Post(string p, object? b = null) => SendAsync(HttpMethod.Post, p, b);
    public Task<(HttpStatusCode Status, JsonElement Body)> Patch(string p, object? b) => SendAsync(HttpMethod.Patch, p, b);
    public Task<(HttpStatusCode Status, JsonElement Body)> Delete(string p) => SendAsync(HttpMethod.Delete, p);
}

public static class Scenario
{
    public const string AdminPass = "integration-admin-pass-1";

    /// <summary>Starts a factory with a fresh database, admin logged in (password changed) and one member.</summary>
    public static async Task<(AppFactory F, ApiClient Admin, ApiClient Member)> StartAsync(PostgresFixture pg, Action<AppFactory>? configure = null)
    {
        var f = new AppFactory { ConnectionString = await pg.CreateDatabaseAsync() };
        configure?.Invoke(f);
        var admin = f.NewClient();
        await admin.LoginAsync("admin", AdminPass);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Post("/me/password", new { current = AdminPass, newPassword = "admin-new-pass-123" })).Status);
        admin = f.NewClient();
        Assert.True(await admin.LoginAsync("admin", "admin-new-pass-123"));
        Assert.Equal(HttpStatusCode.Created, (await admin.Post("/admin/users", new { username = "alice", password = "alice-initial-pass-1", role = "member" })).Status);
        var member = f.NewClient();
        Assert.True(await member.LoginAsync("alice", "alice-initial-pass-1"));
        Assert.Equal(HttpStatusCode.NoContent, (await member.Post("/me/password", new { current = "alice-initial-pass-1", newPassword = "alice-new-pass-1234" })).Status);
        member = f.NewClient();
        Assert.True(await member.LoginAsync("alice", "alice-new-pass-1234"));
        return (f, admin, member);
    }

    public static byte[] Deb(string pkg, string ver, string arch, string? extra = null) => DebBuilder.Build(pkg, ver, arch, extra);
}
