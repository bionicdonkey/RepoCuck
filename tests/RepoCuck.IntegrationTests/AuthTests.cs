using System.Net;
using System.Text.Json;
using RepoCuck.Infrastructure.Auth;

namespace RepoCuck.Tests;

[Collection("pg")]
public class AuthTests(PostgresFixture pg)
{
    [Fact]
    public async Task Anonymous_and_member_access_matrix()
    {
        var (f, admin, member) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        var anon = f.NewClient();
        foreach (var path in new[] { "/repositories", "/requests", "/me", "/admin/users", "/admin/audit", "/admin/settings", "/admin/jobs" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await anon.Get(path)).Status);

        // member: allowed reads, forbidden admin
        foreach (var path in new[] { "/repositories", "/requests", "/me" })
            Assert.Equal(HttpStatusCode.OK, (await member.Get(path)).Status);
        foreach (var path in new[] { "/admin/users", "/admin/audit", "/admin/settings", "/admin/jobs", "/admin/quarantine", "/admin/conflicts", "/admin/requests", "/admin/signing" })
            Assert.Equal(HttpStatusCode.Forbidden, (await member.Get(path)).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Post("/admin/repositories", new { owner = "a", name = "b", architectures = new[] { "amd64" } })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Post("/admin/apt/rebuild")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Post("/admin/signing/rotate", new { action = "start" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Get("/admin/providers")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Delete($"/admin/variants/{Guid.NewGuid()}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Post($"/admin/requests/{Guid.NewGuid()}/approve")).Status);
        Assert.Equal(HttpStatusCode.OK, (await admin.Get("/admin/users")).Status);
    }

    [Fact]
    public async Task Mutations_require_csrf_token_and_same_origin()
    {
        var (f, admin, _) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.SendAsync(HttpMethod.Post, "/admin/apt/rebuild", null, csrf: false)).Status);
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/admin/apt/rebuild");
        req.Headers.Add("Origin", "http://evil.example");
        req.Headers.Add("X-Repocuck-CSRF", "x");
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Http.SendAsync(req)).StatusCode);
        var req2 = new HttpRequestMessage(HttpMethod.Post, "/api/v1/admin/apt/rebuild");
        req2.Headers.Add("Sec-Fetch-Site", "cross-site");
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Http.SendAsync(req2)).StatusCode);
    }

    [Fact]
    public async Task Security_headers_and_error_shape()
    {
        var (f, admin, _) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        var (st, _, resp) = await f.RawGet("/login");
        Assert.Equal(HttpStatusCode.OK, st);
        var csp = string.Join(";", resp.Headers.GetValues("Content-Security-Policy"));
        Assert.Contains("default-src 'self'", csp); Assert.Contains("frame-ancestors 'none'", csp); Assert.Contains("nonce-", csp);
        Assert.Equal("nosniff", resp.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.False(resp.Headers.Contains("Server"));
        Assert.False(resp.Headers.Contains("Strict-Transport-Security"), "no HSTS in http mode");
        var (c, js) = await admin.Get($"/repositories/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, c);
        Assert.Equal("not_found", js.GetProperty("code").GetString());
        Assert.False(js.GetRawText().Contains("   at "), "no stack traces in error bodies");
        var (_, hbody, _) = await f.RawGet("/healthz");
        Assert.DoesNotContain("version", System.Text.Encoding.UTF8.GetString(hbody));
    }

    [Fact]
    public async Task Lockout_blocks_after_repeated_failures_and_admin_can_unlock()
    {
        var (f, admin, _) = await Scenario.StartAsync(pg, x => { x.Settings["REPOCUCK:ROLE"] = "web"; x.Settings["Auth:MaxFailedAttempts"] = "3"; });
        using var _ = f;
        var attacker = f.NewClient();
        for (var i = 0; i < 3; i++) Assert.False(await attacker.LoginAsync("alice", "wrong-password-" + i));
        Assert.False(await attacker.LoginAsync("alice", "alice-new-pass-1234"), "locked even with the right password");
        // another client address is unaffected by the (user, ip) lockout in tests (same IP) – unlock via admin
        var users = await admin.Get("/admin/users");
        var id = users.Body.GetProperty("items").EnumerateArray().First(u => u.GetProperty("username").GetString() == "alice").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Post($"/admin/users/{id}/unlock")).Status);
        Assert.True(await f.NewClient().LoginAsync("alice", "alice-new-pass-1234"));
    }

    [Fact]
    public async Task Last_admin_cannot_be_disabled_or_demoted()
    {
        var (f, admin, _) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        var users = await admin.Get("/admin/users");
        var adminId = users.Body.GetProperty("items").EnumerateArray().First(u => u.GetProperty("username").GetString() == "admin").GetProperty("id").GetGuid();
        var (c1, j1) = await admin.Patch($"/admin/users/{adminId}", new { isActive = false });
        Assert.Equal(HttpStatusCode.Conflict, c1); Assert.Equal("invalid_state", j1.GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await admin.Patch($"/admin/users/{adminId}", new { role = "member" })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.Delete($"/admin/users/{adminId}")).Status);
        // with a second admin the first can be demoted
        var (c, j) = await admin.Post("/admin/users", new { username = "root2", password = "root2-initial-pass-1", role = "admin" });
        Assert.Equal(HttpStatusCode.Created, c);
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/users/{adminId}", new { role = "member" })).Status);
    }

    [Fact]
    public async Task Totp_enrollment_requires_code_at_login_and_recovery_codes_work_once()
    {
        var (f, _, member) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        var (c, js) = await member.Post("/me/totp/enable", new { password = "alice-new-pass-1234" });
        Assert.Equal(HttpStatusCode.OK, c);
        var secret = js.GetProperty("secret").GetString()!;
        var code = Totp.Code(secret, Totp.CounterAt(DateTimeOffset.UtcNow));
        var (c2, js2) = await member.Post("/me/totp/confirm", new { code });
        Assert.Equal(HttpStatusCode.OK, c2);
        var recovery = js2.GetProperty("recoveryCodes").EnumerateArray().Select(x => x.GetString()!).ToList();
        Assert.Equal(10, recovery.Count);

        // password alone no longer signs in
        Assert.False(await f.NewClient().LoginAsync("alice", "alice-new-pass-1234"));
        // login with a recovery code (single use)
        var rc = recovery[0];
        var ok = await LoginWithTotp(f, "alice", "alice-new-pass-1234", rc);
        Assert.True(ok);
        Assert.False(await LoginWithTotp(f, "alice", "alice-new-pass-1234", rc), "recovery code is single-use");
    }

    private static async Task<bool> LoginWithTotp(AppFactory f, string user, string pw, string code)
    {
        var http = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
        var page = await http.GetStringAsync("/login");
        var tok = System.Text.RegularExpressions.Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var resp = await http.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["Username"] = user, ["Password"] = pw, ["TotpCode"] = code, ["__RequestVerificationToken"] = tok }));
        return resp.StatusCode == HttpStatusCode.Redirect && resp.Headers.Location?.OriginalString.Contains("/login") != true;
    }

    [Fact]
    public async Task Revoking_sessions_invalidates_existing_cookie()
    {
        var (f, _, member) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        Assert.Equal(HttpStatusCode.OK, (await member.Get("/me")).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await member.Post("/me/sessions/revoke-all")).Status);
        await Task.Delay(31_000); // user-state cache is 30 s
        Assert.Equal(HttpStatusCode.Unauthorized, (await member.Get("/me")).Status);
    }

    [Theory]
    [InlineData("short", false)]
    [InlineData("alicealicealice", true)]
    [InlineData("password12345", false)]
    [InlineData("aaaaaaaaaaaaaa", false)]
    [InlineData("a-decent-passphrase-1", true)]
    public void Password_policy(string pw, bool ok) => Assert.Equal(ok, UserService.ValidatePassword(pw, "alice") is null);
}
