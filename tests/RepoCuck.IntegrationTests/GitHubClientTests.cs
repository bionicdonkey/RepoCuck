using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.GitHub;

namespace RepoCuck.Tests;

/// <summary>Scripted loopback HTTP server standing in for api.github.com and the asset CDN.</summary>
public sealed class ScriptedServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    public Func<HttpContext, Task> Handler { get; set; } = _ => Task.CompletedTask;
    public List<(string Path, string? Auth, string? IfNoneMatch, string Host)> Requests { get; } = new();
    public string Base { get; private set; } = "";
    private ScriptedServer(WebApplication app) => _app = app;

    public static async Task<ScriptedServer> StartAsync()
    {
        var app = WebApplication.CreateSlimBuilder().Build();
        var s = new ScriptedServer(app);
        app.Run(async ctx =>
        {
            lock (s.Requests) s.Requests.Add((ctx.Request.Path + ctx.Request.QueryString, ctx.Request.Headers.Authorization.ToString().NullIfEmpty(), ctx.Request.Headers.IfNoneMatch.ToString().NullIfEmpty(), ctx.Request.Host.Host));
            await s.Handler(ctx);
        });
        app.Urls.Add("http://127.0.0.1:0");
        await app.StartAsync();
        s.Base = app.Urls.First().TrimEnd('/');
        return s;
    }

    public int Port => new Uri(Base).Port;
    public async ValueTask DisposeAsync() { await _app.StopAsync(); await _app.DisposeAsync(); }
}

internal static class StringExt { public static string? NullIfEmpty(this string s) => s.Length == 0 ? null : s; }

[Collection("pg")]
public class GitHubClientTests(PostgresFixture pg)
{
    private const string RepoJson = "{\"id\":42,\"name\":\"tool\",\"full_name\":\"acme/tool\",\"private\":false,\"html_url\":\"https://github.com/acme/tool\",\"owner\":{\"login\":\"acme\"},\"license\":{\"spdx_id\":\"MIT\"},\"default_branch\":\"main\",\"archived\":false}";

    private async Task<(GitHubClient Client, ServiceProvider Sp)> Make(ScriptedServer srv, Action<GitHubOptions>? cfg = null)
    {
        var cs = await pg.CreateDatabaseAsync();
        var ds = NpgsqlDataSource.Create(cs);
        await MigrationRunner.ApplyAsync(ds, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, default);
        GitHubClient.BackoffBase = TimeSpan.FromMilliseconds(1);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(ds);
        services.AddDbContextFactory<AppDbContext>((sp, o) => o.UseNpgsql(sp.GetRequiredService<NpgsqlDataSource>()).UseSnakeCaseNamingConvention());
        services.Configure<GitHubOptions>(o =>
        {
            o.ApiBaseUrl = srv.Base; o.AllowInsecureForTesting = true; o.Token = "tok123"; o.AssetHostAllowList = "localhost";
            cfg?.Invoke(o);
        });
        services.AddHttpClient(GitHubClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(sp => GitHubClient.CreateHandler(sp.GetRequiredService<IOptions<GitHubOptions>>().Value));
        services.AddSingleton<GitHubClient>();
        var sp = services.BuildServiceProvider();
        return (sp.GetRequiredService<GitHubClient>(), sp);
    }

    private static Task Json(HttpContext c, string body, int status = 200, Action<IHeaderDictionary>? headers = null)
    {
        c.Response.StatusCode = status; c.Response.ContentType = "application/json";
        c.Response.Headers["X-RateLimit-Limit"] = "5000"; c.Response.Headers["X-RateLimit-Remaining"] = "4000";
        headers?.Invoke(c.Response.Headers);
        return c.Response.WriteAsync(body);
    }

    [Fact]
    public async Task Repo_lookup_sends_expected_headers_and_maps_errors()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var (client, sp) = await Make(srv);
        using var _ = sp;
        srv.Handler = c => c.Request.Path.Value switch
        {
            "/repos/acme/tool" => Json(c, RepoJson),
            "/repos/acme/secret" => Json(c, RepoJson.Replace("\"private\":false", "\"private\":true")),
            _ => Json(c, "{\"message\":\"Not Found\"}", 404),
        };
        var r = await client.GetRepoAsync("acme", "tool", default);
        Assert.Equal((42L, "acme/tool", "MIT"), (r.Id, r.FullName, r.License));
        var req = srv.Requests[0];
        Assert.Equal("Bearer tok123", req.Auth);
        Assert.Equal("not_found", (await Assert.ThrowsAsync<GitHubException>(() => client.GetRepoAsync("acme", "nope", default))).Code);
        Assert.Equal("not_found", (await Assert.ThrowsAsync<GitHubException>(() => client.GetRepoAsync("acme", "secret", default))).Code);   // private repos are not public
        Assert.True(client.RateLimitRemainingPercent is >= 79 and <= 81);
    }

    [Fact]
    public async Task Conditional_requests_reuse_the_cached_payload_on_304()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var (client, sp) = await Make(srv);
        using var _ = sp;
        srv.Handler = c =>
        {
            if (c.Request.Headers.IfNoneMatch == "\"v1\"") { c.Response.StatusCode = 304; return Task.CompletedTask; }
            return Json(c, "[{\"id\":7,\"tag_name\":\"v1\",\"draft\":false,\"prerelease\":false,\"assets\":[]},{\"id\":8,\"tag_name\":\"d\",\"draft\":true,\"assets\":[]}]", headers: h => h.ETag = "\"v1\"");
        };
        var first = await client.GetReleasesAsync("acme", "tool", 10, default);
        var second = await client.GetReleasesAsync("acme", "tool", 10, default);
        Assert.Single(first); Assert.Equal("v1", second[0].Tag);               // drafts filtered
        Assert.Null(srv.Requests[0].IfNoneMatch); Assert.Equal("\"v1\"", srv.Requests[1].IfNoneMatch);
    }

    [Fact]
    public async Task Pagination_follows_link_headers_and_respects_the_cap()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var (client, sp) = await Make(srv);
        using var _ = sp;
        srv.Handler = c =>
        {
            var page = c.Request.Query["page"].ToString();
            var items = page == "2" ? "[{\"id\":3,\"tag_name\":\"c\",\"assets\":[]},{\"id\":4,\"tag_name\":\"d\",\"assets\":[]}]" : "[{\"id\":1,\"tag_name\":\"a\",\"assets\":[]},{\"id\":2,\"tag_name\":\"b\",\"assets\":[]}]";
            return Json(c, items, headers: h => { if (page != "2") h["Link"] = $"<{srv.Base}/repos/acme/tool/releases?per_page=100&page=2>; rel=\"next\""; });
        };
        Assert.Equal(["a", "b", "c", "d"], (await client.GetReleasesAsync("acme", "tool", 10, default)).Select(r => r.Tag));
        Assert.Equal(["a", "b", "c"], (await client.GetReleasesAsync("acme", "tool", 3, default)).Select(r => r.Tag));
    }

    [Fact]
    public async Task Transient_errors_are_retried_but_client_errors_are_not()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var (client, sp) = await Make(srv);
        using var _ = sp;
        var calls = 0;
        srv.Handler = c => ++calls < 3 ? Json(c, "{}", 503) : Json(c, RepoJson);
        Assert.Equal(42, (await client.GetRepoAsync("acme", "tool", default)).Id);
        Assert.Equal(3, calls);

        calls = 0; srv.Handler = c => { calls++; return Json(c, "{}", 502); };
        var ex = await Assert.ThrowsAsync<GitHubException>(() => client.GetRepoAsync("acme", "tool", default));
        Assert.True(ex.Transient); Assert.Equal(4, calls);                       // 1 try + 3 retries

        calls = 0; srv.Handler = c => { calls++; return Json(c, "{\"message\":\"Validation\"}", 422); };
        Assert.False((await Assert.ThrowsAsync<GitHubException>(() => client.GetRepoAsync("acme", "tool", default))).Transient);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Rate_limit_responses_surface_the_reset_time()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var (client, sp) = await Make(srv);
        using var _ = sp;
        var reset = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
        srv.Handler = c => Json(c, "{\"message\":\"API rate limit exceeded\"}", 403, h => { h["X-RateLimit-Remaining"] = "0"; h["X-RateLimit-Reset"] = reset.ToString(); });
        var e = await Assert.ThrowsAsync<GitHubRateLimitedException>(() => client.GetRepoAsync("acme", "tool", default));
        Assert.Equal(reset, e.ResetAt.ToUnixTimeSeconds());
        Assert.Equal(0, client.RateLimitRemainingPercent);

        srv.Handler = c => Json(c, "{}", 429, h => h["Retry-After"] = "120");
        var e2 = await Assert.ThrowsAsync<GitHubRateLimitedException>(() => client.GetRepoAsync("acme", "tool", default));
        Assert.InRange((e2.ResetAt - DateTimeOffset.UtcNow).TotalSeconds, 100, 125);
    }

    [Fact]
    public async Task Downloads_hash_enforce_size_follow_safe_redirects_and_never_leak_the_token()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var (client, sp) = await Make(srv);
        using var _ = sp;
        var data = RandomNumberGenerator.GetBytes(50_000);
        var tmp = Path.Combine(Path.GetTempPath(), "rc-dl-" + Guid.NewGuid().ToString("N"));
        srv.Handler = async c =>
        {
            switch (c.Request.Path.Value)
            {
                case "/direct": c.Response.ContentLength = data.Length; await c.Response.Body.WriteAsync(data); break;
                case "/hop": c.Response.StatusCode = 302; c.Response.Headers.Location = $"http://localhost:{srv.Port}/cdn"; break;   // different host name -> token must be dropped
                case "/cdn": c.Response.ContentLength = data.Length; await c.Response.Body.WriteAsync(data); break;
                case "/evil": c.Response.StatusCode = 302; c.Response.Headers.Location = "http://169.254.169.254/latest/meta-data"; break;
                case "/creds": c.Response.StatusCode = 302; c.Response.Headers.Location = $"http://user:pw@localhost:{srv.Port}/cdn"; break;
                case "/loop": c.Response.StatusCode = 302; c.Response.Headers.Location = "/loop"; break;
                case "/gone": c.Response.StatusCode = 404; break;
                default: c.Response.StatusCode = 500; break;
            }
        };
        GhAsset A(string p, long size = 50_000) => new(1, "x.deb", size, null, null, 0, srv.Base + p);

        var ok = await client.DownloadAssetAsync(A("/direct"), 1 << 20, tmp, default);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), ok.Sha256);
        Assert.Equal(Convert.ToHexStringLower(SHA512.HashData(data)), ok.Sha512);
        Assert.Equal(data, await File.ReadAllBytesAsync(ok.TempPath));
        Assert.Equal("Bearer tok123", srv.Requests.Last(r => r.Path == "/direct").Auth);        // API host gets the token

        var viaHop = await client.DownloadAssetAsync(A("/hop"), 1 << 20, tmp, default);
        Assert.Equal(ok.Sha256, viaHop.Sha256);
        Assert.Null(srv.Requests.Last(r => r.Path == "/cdn").Auth);                              // different host: no Authorization header
        Assert.Equal("localhost", srv.Requests.Last(r => r.Path == "/cdn").Host);

        Assert.Equal("too_large", (await Assert.ThrowsAsync<GitHubException>(() => client.DownloadAssetAsync(A("/direct"), 10_000, tmp, default))).Code);
        Assert.Equal("size_mismatch", (await Assert.ThrowsAsync<GitHubException>(() => client.DownloadAssetAsync(A("/direct", 123), 1 << 20, tmp, default))).Code);
        Assert.Contains("allow-list", (await Assert.ThrowsAsync<GitHubException>(() => client.DownloadAssetAsync(A("/evil"), 1 << 20, tmp, default))).Message);
        Assert.Contains("User-info", (await Assert.ThrowsAsync<GitHubException>(() => client.DownloadAssetAsync(A("/creds"), 1 << 20, tmp, default))).Message);
        Assert.Contains("redirects", (await Assert.ThrowsAsync<GitHubException>(() => client.DownloadAssetAsync(A("/loop"), 1 << 20, tmp, default))).Message);
        Assert.Equal("not_found", (await Assert.ThrowsAsync<GitHubException>(() => client.DownloadAssetAsync(A("/gone"), 1 << 20, tmp, default))).Code);
        Assert.Empty(Directory.GetFiles(tmp).Except([ok.TempPath, viaHop.TempPath]));            // failed downloads leave no temp files behind
    }

    [Fact]
    public async Task Production_handler_refuses_connections_to_private_addresses()
    {
        await using var srv = await ScriptedServer.StartAsync();
        srv.Handler = c => c.Response.WriteAsync("should never be reached");
        using var http = new HttpClient(GitHubClient.CreateHandler(new GitHubOptions { AllowInsecureForTesting = false }));
        var e = await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync(srv.Base + "/"));       // 127.0.0.1 is loopback
        Assert.Contains("non-public", e.Message + e.InnerException?.Message);
        Assert.Empty(srv.Requests);
    }

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.169.254", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("224.0.0.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("140.82.112.3", false)]
    [InlineData("::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fc00::1", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("::ffff:10.0.0.1", true)]
    [InlineData("::ffff:8.8.8.8", false)]
    [InlineData("2606:4700::1111", false)]
    public void Private_address_classification(string ip, bool isPrivate) => Assert.Equal(isPrivate, GitHubClient.IsPrivate(IPAddress.Parse(ip)));
}

[Collection("pg")]
public class RateLimitWindowTests(PostgresFixture pg)
{
    [Fact]
    public async Task Exhausted_quota_is_assumed_restored_once_the_reset_time_passes()
    {
        await using var srv = await ScriptedServer.StartAsync();
        var cs = await pg.CreateDatabaseAsync();
        var ds = NpgsqlDataSource.Create(cs);
        await MigrationRunner.ApplyAsync(ds, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, default);
        var services = new ServiceCollection();
        services.AddLogging(); services.AddSingleton(ds);
        services.AddDbContextFactory<AppDbContext>((sp, o) => o.UseNpgsql(sp.GetRequiredService<NpgsqlDataSource>()).UseSnakeCaseNamingConvention());
        services.Configure<GitHubOptions>(o => { o.ApiBaseUrl = srv.Base; o.AllowInsecureForTesting = true; });
        services.AddHttpClient(GitHubClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(sp => GitHubClient.CreateHandler(sp.GetRequiredService<IOptions<GitHubOptions>>().Value));
        services.AddSingleton<GitHubClient>();
        using var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<GitHubClient>();
        var reset = DateTimeOffset.UtcNow.AddSeconds(2).ToUnixTimeSeconds();
        srv.Handler = c =>
        {
            c.Response.StatusCode = 404; c.Response.Headers["X-RateLimit-Limit"] = "60"; c.Response.Headers["X-RateLimit-Remaining"] = "1"; c.Response.Headers["X-RateLimit-Reset"] = reset.ToString();
            return Task.CompletedTask;
        };
        await Assert.ThrowsAsync<GitHubException>(() => client.GetRepoAsync("a", "b", default));
        Assert.True(client.RateLimitRemainingPercent < 10, "job runner pauses while quota is nearly exhausted");
        await Task.Delay(TimeSpan.FromSeconds(3));
        Assert.Equal(100, client.RateLimitRemainingPercent);       // otherwise the runner would never claim a job again
    }
}

[Collection("pg")]
public class CrashRecoveryTests(PostgresFixture pg)
{
    [Fact]
    public async Task Interrupted_runs_and_generations_are_failed_at_startup()
    {
        var cs = await pg.CreateDatabaseAsync();
        using (var first = new AppFactory { ConnectionString = cs })
        {
            first.Settings["REPOCUCK:ROLE"] = "web";
            first.CreateClient();
            first.GitHub.AddRepo("acme/x", 1);
            await first.WithDbAsync(async db =>
            {
                var repoId = Guid.NewGuid();
                db.Repositories.Add(new Domain.Repository { Id = repoId, GithubRepoId = 1, Owner = "a", Name = "x", FullName = "a/x", HtmlUrl = "u", CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow });
                await db.SaveChangesAsync();
                db.SyncRuns.Add(new Domain.SyncRun { Id = Guid.NewGuid(), RepositoryId = repoId, StartedAt = DateTimeOffset.UtcNow, Status = "running" });
                var suite = await db.AptSuites.FirstAsync();
                db.AptGenerations.Add(new Domain.AptGeneration { Id = Guid.NewGuid(), SuiteId = suite.Id, GenerationNo = 99, Status = "building", CreatedAt = DateTimeOffset.UtcNow });
                await db.SaveChangesAsync();
                return 0;
            });
        }
        using var second = new AppFactory { ConnectionString = cs };
        second.Settings["REPOCUCK:ROLE"] = "web";
        second.CreateClient();                   // startup runs the recovery step
        Assert.Equal(0, await second.WithDbAsync(db => db.SyncRuns.CountAsync(r => r.Status == "running")));
        Assert.Equal(0, await second.WithDbAsync(db => db.AptGenerations.CountAsync(g => g.Status == "building")));
        Assert.Equal("interrupted", await second.WithDbAsync(db => db.SyncRuns.Select(r => r.ErrorCategory).FirstAsync()));
    }
}
