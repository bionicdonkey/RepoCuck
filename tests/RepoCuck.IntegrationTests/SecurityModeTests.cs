using System.Net;
using Microsoft.EntityFrameworkCore;

namespace RepoCuck.Tests;

[Collection("pg")]
public class SecurityModeTests(PostgresFixture pg)
{
    private async Task<AppFactory> Make(Action<AppFactory> cfg)
    {
        var f = new AppFactory { ConnectionString = await pg.CreateDatabaseAsync() };
        f.Settings["REPOCUCK:ROLE"] = "web";
        cfg(f);
        return f;
    }

    private static void HttpsFront(AppFactory f, string peer = "10.1.2.3")
    {
        f.Settings["Security:PublicScheme"] = "https";
        f.Settings["REPOCUCK:BASE_URL"] = "https://apt.example.com";
        f.Settings["Security:TrustedProxies"] = "10.0.0.0/8";
        f.Settings["Security:ClientIpHeader"] = "CF-Connecting-IP";
        f.PeerAddress = peer;
    }

    [Fact]
    public async Task Https_mode_redirects_plain_http_but_trusts_proxy_forwarded_proto()
    {
        using var f = await Make(x => HttpsFront(x));
        var (st, _, r) = await f.RawGet("/login", q => q.Headers.Host = "apt.example.com");
        Assert.Equal(HttpStatusCode.MovedPermanently, st);                              // plain http, no forwarded proto
        Assert.Equal("https://apt.example.com/login", r.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.OK, (await f.RawGet("/healthz")).Status);              // health checks are exempt
        Assert.Equal(HttpStatusCode.OK, (await f.RawGet("/readyz")).Status);

        var (post, _, _) = await f.RawGet("/login", q => { q.Headers.Host = "apt.example.com"; }, HttpMethod.Post);
        Assert.Equal(HttpStatusCode.BadRequest, post);                                    // never accept credentials over http

        var (ok, _, resp) = await f.RawGet("/login", q => { q.Headers.Host = "apt.example.com"; q.Headers.Add("X-Forwarded-Proto", "https"); });
        Assert.Equal(HttpStatusCode.OK, ok);
        Assert.Contains("max-age=", string.Join(",", resp.Headers.GetValues("Strict-Transport-Security")));
        var cookies = string.Join("|", resp.Headers.GetValues("Set-Cookie"));
        Assert.Contains("__Host-repocuck.af", cookies); Assert.Contains("secure", cookies, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Forwarded_headers_from_untrusted_peers_are_ignored()
    {
        using var f = await Make(x => HttpsFront(x, peer: "203.0.113.50"));
        var (st, _, _) = await f.RawGet("/login", q => { q.Headers.Host = "apt.example.com"; q.Headers.Add("X-Forwarded-Proto", "https"); });
        Assert.Equal(HttpStatusCode.MovedPermanently, st);                                // spoofed proto from an untrusted peer does not count
    }

    [Fact]
    public async Task Client_ip_header_is_honoured_only_from_trusted_proxy()
    {
        foreach (var (peer, expected) in new[] { ("10.1.2.3", "198.51.100.7"), ("203.0.113.50", "203.0.113.50") })
        {
            using var f = await Make(x => { HttpsFront(x, peer); x.Settings["Security:PublicScheme"] = "http"; x.Settings["REPOCUCK:BASE_URL"] = "http://apt.example.com"; });
            var c = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
            var page = await c.GetStringAsync("/login");
            var tok = System.Text.RegularExpressions.Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
            var req = new HttpRequestMessage(HttpMethod.Post, "/login") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["Username"] = "nobody", ["Password"] = "x", ["__RequestVerificationToken"] = tok }) };
            req.Headers.Add("CF-Connecting-IP", "198.51.100.7");
            await c.SendAsync(req);
            var ip = await f.WithDbAsync(db => db.AuditLog.Where(a => a.Action == "auth.login").OrderByDescending(a => a.Id).Select(a => a.ActorIp!.ToString()).FirstOrDefaultAsync());
            Assert.Equal(expected, ip);
        }
    }

    [Fact]
    public async Task Startup_validation_rejects_unsafe_configuration()
    {
        using (var f = await Make(x => x.Settings["REPOCUCK:BASE_URL"] = ""))
            Assert.Throws<InvalidOperationException>(() => f.CreateClient());
        using (var f = await Make(x => { x.Settings["Security:PublicScheme"] = "https"; x.Settings["REPOCUCK:BASE_URL"] = "http://x.example"; }))
            Assert.Throws<InvalidOperationException>(() => f.CreateClient());                    // scheme mismatch
        using (var f = await Make(x => { x.Settings["Security:PublicScheme"] = "https"; x.Settings["REPOCUCK:BASE_URL"] = "https://x.example"; }))
            Assert.Throws<InvalidOperationException>(() => f.CreateClient());                    // https but no TLS front configured
        using (var f = await Make(x => { x.Settings["Security:PublicScheme"] = "ftp"; }))
            Assert.Throws<InvalidOperationException>(() => f.CreateClient());
        using (var f = await Make(x => { x.Settings["Security:PublicScheme"] = "https"; x.Settings["REPOCUCK:BASE_URL"] = "https://x.example"; x.Settings["Security:AssumeTlsFront"] = "true"; }))
            Assert.NotNull(f.CreateClient());
    }

    [Fact]
    public async Task Login_posts_are_rate_limited_per_ip_but_reads_are_not()
    {
        using var f = await Make(x => x.Settings["Limits:LoginAttemptsPer5MinutesPerIp"] = "3");
        var c = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            var page = await c.GetStringAsync("/login");            // GETs never count
            var tok = System.Text.RegularExpressions.Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
            var r = await c.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string> { ["Username"] = "x", ["Password"] = "y", ["__RequestVerificationToken"] = tok }));
            codes.Add(r.StatusCode);
            if (r.StatusCode == HttpStatusCode.TooManyRequests) Assert.True(r.Headers.Contains("Retry-After"));
        }
        Assert.Equal(3, codes.Count(x => x == HttpStatusCode.OK));
        Assert.Equal(2, codes.Count(x => x == HttpStatusCode.TooManyRequests));
    }

    [Fact]
    public async Task Apt_endpoint_has_its_own_rate_limiter_with_burst_headroom()
    {
        using var f = await Make(x => { });
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 160; i++) statuses.Add((await f.RawGet("/apt/dists/stable/InRelease")).Status);
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);
        Assert.True(statuses.Take(90).All(s => s != HttpStatusCode.TooManyRequests), "burst of ~100 is allowed");
    }

    [Fact]
    public async Task First_run_setup_token_flow_creates_admin_once()
    {
        using var f = await Make(x => { x.Settings["Bootstrap:AdminUsername"] = ""; x.Settings["Bootstrap:AdminPasswordFile"] = ""; });
        var c = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
        Assert.Equal(HttpStatusCode.OK, (await c.GetAsync("/setup")).StatusCode);
        var page = await c.GetStringAsync("/setup");
        var tok = System.Text.RegularExpressions.Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var bad = await c.PostAsync("/setup", new FormUrlEncodedContent(new Dictionary<string, string> { ["Token"] = "nope", ["Username"] = "root", ["Password"] = "root-password-123", ["__RequestVerificationToken"] = tok }));
        Assert.Equal(HttpStatusCode.OK, bad.StatusCode);
        Assert.Contains("Invalid or expired setup token", await bad.Content.ReadAsStringAsync());
        var token = f.Services.GetService(typeof(RepoCuck.Infrastructure.SetupTokenService)) as RepoCuck.Infrastructure.SetupTokenService;
        var real = token!.Issue();
        page = await c.GetStringAsync("/setup");
        tok = System.Text.RegularExpressions.Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var ok = await c.PostAsync("/setup", new FormUrlEncodedContent(new Dictionary<string, string> { ["Token"] = real, ["Username"] = "root", ["Password"] = "root-password-123", ["__RequestVerificationToken"] = tok }));
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/setup")).StatusCode);        // closed after the first admin exists
        var api = f.NewClient();
        Assert.True(await api.LoginAsync("root", "root-password-123"));
        Assert.Equal("admin", (await api.Get("/me")).Body.GetProperty("role").GetString());
    }
}
