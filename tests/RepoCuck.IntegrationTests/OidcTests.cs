using System.Net;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Domain;

namespace RepoCuck.Tests;

[Collection("pg")]
public class OidcTests(PostgresFixture pg)
{
    private static async Task<(AppFactory F, ApiClient Admin, MockIdp Idp, Guid ProviderId)> Setup(PostgresFixture pg, Action<AppFactory>? cfg = null, bool withMapping = true)
    {
        var idp = await MockIdp.StartAsync();
        var (f, admin, _) = await Scenario.StartAsync(pg, x => { x.Settings["REPOCUCK:ROLE"] = "web"; x.Settings["Auth:AllowInsecureOidc"] = "true"; cfg?.Invoke(x); });
        var (c, js) = await admin.Post("/admin/providers", new { slug = "mock", displayName = "Mock IdP", authority = idp.Issuer, clientId = MockIdp.ClientId, clientSecret = MockIdp.ClientSecret });
        Assert.Equal(HttpStatusCode.Created, c);
        var id = js.GetProperty("id").GetGuid();
        if (withMapping)
            Assert.Equal(HttpStatusCode.NoContent, (await admin.SendAsync(HttpMethod.Put, $"/admin/providers/{id}/mappings",
                new[] { new { claimValue = "rc-admins", role = "admin", priority = 10 }, new { claimValue = "rc-users", role = "member", priority = 0 } })).Status);
        return (f, admin, idp, id);
    }

    /// <summary>Drives the browser-side dance: RP signin -> IdP authorize -> RP callback. Returns the client and the final redirect.</summary>
    private static async Task<(HttpClient Client, HttpResponseMessage Final)> Browser(AppFactory f, MockIdp idp, HttpClient? existing = null, string path = "/auth/oidc/mock/signin?returnUrl=/repos")
    {
        var client = existing ?? f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
        var start = await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        using var idpHttp = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var authz = await idpHttp.GetAsync(start.Headers.Location!);
        Assert.Equal(HttpStatusCode.Redirect, authz.StatusCode);
        var cb = authz.Headers.Location!;
        var final = await client.GetAsync(cb.PathAndQuery);
        return (client, final);
    }

    private static async Task<string> Me(HttpClient c, string field)
    {
        var r = await c.GetAsync("/api/v1/me");
        if (r.StatusCode != HttpStatusCode.OK) return "(" + (int)r.StatusCode + ")";
        return System.Text.Json.JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement.GetProperty(field).ToString();
    }

    [Fact]
    public async Task Login_provisions_member_by_default_and_admin_via_group_mapping_and_follows_group_changes()
    {
        var (f, admin, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        idp.User = new IdpUser { Subject = "u1", Username = "John.Doe", Email = "john@example.com", Groups = ["rc-users"] };
        var (c1, fin) = await Browser(f, idp);
        Assert.Equal(HttpStatusCode.Redirect, fin.StatusCode);
        Assert.Equal("/repos", fin.Headers.Location!.OriginalString);
        Assert.Equal("member", await Me(c1, "role"));
        Assert.Equal("john.doe", await Me(c1, "username"));
        Assert.True(idp.LastChallengeMethod == "S256", "PKCE S256 is used");
        Assert.Equal("mock", System.Text.Json.JsonDocument.Parse(await c1.GetStringAsync("/api/v1/me")).RootElement.GetProperty("linkedProviders")[0].GetString());

        // promoted by group on the next login
        idp.User = new IdpUser { Subject = "u1", Username = "John.Doe", Email = "john@example.com", Groups = ["rc-admins"] };
        var (c2, _) = await Browser(f, idp);
        Assert.Equal("admin", await Me(c2, "role"));
        Assert.Equal(HttpStatusCode.OK, (await c2.GetAsync("/api/v1/admin/users")).StatusCode);
        // demoted when the group is removed (another admin exists so the guard does not interfere)
        idp.User = new IdpUser { Subject = "u1", Username = "John.Doe", Email = "john@example.com", Groups = [] };
        var (c3, _) = await Browser(f, idp);
        Assert.Equal("member", await Me(c3, "role"));
        Assert.Equal(HttpStatusCode.Forbidden, (await c3.GetAsync("/api/v1/admin/users")).StatusCode);
        // one user row only
        Assert.Equal(1, await f.WithDbAsync(db => db.Users.CountAsync(u => u.Username == "john.doe")));
        var audit = await admin.Get("/admin/audit?limit=200");
        Assert.Contains(audit.Body.GetProperty("items").EnumerateArray(), a => a.GetProperty("action").GetString() == "user.provisioned");
        Assert.Contains(audit.Body.GetProperty("items").EnumerateArray(), a => a.GetProperty("action").GetString() == "user.role_changed");
    }

    [Fact]
    public async Task Username_collisions_get_numeric_suffix_and_pinned_roles_are_not_overwritten()
    {
        var (f, admin, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        idp.User = new IdpUser { Subject = "a", Username = "alice", Email = "a1@example.com" };   // collides with the local user "alice"
        var (c1, _) = await Browser(f, idp);
        Assert.Equal("alice2", await Me(c1, "username"));
        // the admin pins this user's role; a group mapping must not override it
        var users = await admin.Get("/admin/users");
        var id = users.Body.GetProperty("items").EnumerateArray().First(u => u.GetProperty("username").GetString() == "alice2").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/users/{id}", new { role = "member" })).Status);
        idp.User = new IdpUser { Subject = "a", Username = "alice", Email = "a1@example.com", Groups = ["rc-admins"] };
        var (c2, _) = await Browser(f, idp);
        Assert.Equal("member", await Me(c2, "role"));
    }

    [Fact]
    public async Task Last_admin_is_never_demoted_by_the_idp_and_disabled_users_are_refused()
    {
        var (f, admin, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        // make the only local admin a member so the SSO user is the only admin, then drop the group
        idp.User = new IdpUser { Subject = "boss", Username = "boss", Email = "boss@example.com", Groups = ["rc-admins"] };
        var (c1, _) = await Browser(f, idp);
        Assert.Equal("admin", await Me(c1, "role"));
        var users = await admin.Get("/admin/users");
        var localAdmin = users.Body.GetProperty("items").EnumerateArray().First(u => u.GetProperty("username").GetString() == "admin").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/users/{localAdmin}", new { role = "member" })).Status);
        idp.User = new IdpUser { Subject = "boss", Username = "boss", Email = "boss@example.com", Groups = [] };
        var (c2, _) = await Browser(f, idp);
        Assert.Equal("admin", await Me(c2, "role"));        // protected: the instance keeps an admin
        // disabling the user blocks SSO login
        var bossId = (await f.WithDbAsync(db => db.Users.Where(u => u.Username == "boss").Select(u => u.Id).FirstAsync()));
        var boss = f.NewClient();   // use the SSO admin session to disable the other admin first so "boss" isn't the last
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/users/{localAdmin}", new { role = "admin" })).Status);
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/users/{bossId}", new { isActive = false })).Status);
        var (_, fin) = await Browser(f, idp);
        Assert.StartsWith("/login?error=", fin.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Unverified_email_and_disabled_auto_provisioning_are_rejected()
    {
        var (f, admin, idp, pid) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        idp.User = new IdpUser { Subject = "x1", Username = "x1", Email = "x1@example.com", EmailVerified = false };
        var (_, fin) = await Browser(f, idp);
        Assert.Contains("not%20verified", fin.Headers.Location!.OriginalString);
        Assert.Equal(0, await f.WithDbAsync(db => db.Users.CountAsync(u => u.Username == "x1")));

        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/providers/{pid}", new { requireVerifiedEmail = false })).Status);
        var (c2, fin2) = await Browser(f, idp);
        Assert.Equal("/repos", fin2.Headers.Location!.OriginalString);

        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/providers/{pid}", new { autoProvision = false })).Status);
        idp.User = new IdpUser { Subject = "new-person", Username = "np", Email = "np@example.com" };
        var (_, fin3) = await Browser(f, idp);
        Assert.Contains("provisioned", Uri.UnescapeDataString(fin3.Headers.Location!.OriginalString));
        // existing identity still works
        idp.User = new IdpUser { Subject = "x1", Username = "x1", Email = "x1@example.com" };
        var (_, fin4) = await Browser(f, idp);
        Assert.Equal("/repos", fin4.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Invalid_tokens_are_rejected()
    {
        var (f, _, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        idp.User = new IdpUser { Subject = "t1", Username = "t1", Email = "t1@example.com" };
        async Task<string> Attempt(Func<Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor, Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor> mutate, System.Security.Cryptography.RSA? signer = null)
        {
            idp.Mutate = mutate; idp.SigningOverride = signer;
            try { var (c, fin) = await Browser(f, idp); return fin.Headers.Location?.OriginalString + "|" + await Me(c, "role"); }
            finally { idp.Mutate = null; idp.SigningOverride = null; }
        }
        foreach (var (name, result) in new[]
        {
            ("wrong audience", await Attempt(d => { d.Audience = "someone-else"; return d; })),
            ("wrong issuer", await Attempt(d => { d.Issuer = "http://evil.example"; return d; })),
            ("expired", await Attempt(d => { d.NotBefore = DateTime.UtcNow.AddHours(-3); d.IssuedAt = DateTime.UtcNow.AddHours(-3); d.Expires = DateTime.UtcNow.AddHours(-2); return d; })),
            ("bad signature", await Attempt(d => d, System.Security.Cryptography.RSA.Create(2048))),
            ("wrong nonce", await Attempt(d => { d.Claims["nonce"] = "not-the-nonce"; return d; })),
            ("no subject", await Attempt(d => { d.Claims.Remove("sub"); return d; })),
        })
            Assert.True(result.StartsWith("/login?error=") && result.EndsWith("|(401)"), $"{name}: {result}");
        Assert.Equal(0, await f.WithDbAsync(db => db.Users.CountAsync(u => u.Username == "t1")));
    }

    [Fact]
    public async Task Authorization_codes_cannot_be_replayed_and_state_must_match()
    {
        var (f, _, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        idp.User = new IdpUser { Subject = "r1", Username = "r1", Email = "r1@example.com" };
        var client = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
        var start = await client.GetAsync("/auth/oidc/mock/signin");
        using var idpHttp = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var cb = (await idpHttp.GetAsync(start.Headers.Location!)).Headers.Location!;
        var tampered = Regex.Replace(cb.PathAndQuery, "state=[^&]+", "state=forged");
        var bad = await client.GetAsync(tampered);
        Assert.StartsWith("/login?error=", bad.Headers.Location!.OriginalString);          // CSRF/state mismatch
        var other = f.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });     // a different browser cannot complete the flow
        var stolen = await other.GetAsync(cb.PathAndQuery);
        Assert.StartsWith("/login?error=", stolen.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Rp_initiated_logout_goes_through_the_provider_and_clears_the_session()
    {
        var (f, _, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        idp.User = new IdpUser { Subject = "l1", Username = "l1user", Email = "l1@example.com" };
        var (client, _) = await Browser(f, idp);
        Assert.Equal("l1user", await Me(client, "username"));
        var page = await client.GetStringAsync("/account");
        var tok = Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var resp = await client.PostAsync("/auth/logout", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = tok }));
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        var loc = resp.Headers.Location!.ToString();
        Assert.StartsWith(idp.Issuer + "/logout", loc);
        Assert.Contains("id_token_hint=", loc);
        Assert.Contains("post_logout_redirect_uri=", loc);
        Assert.Equal("(401)", await Me(client, "role"));
    }

    [Fact]
    public async Task Linking_requires_reauthentication_and_unlinking_is_refused_for_the_only_credential()
    {
        var (f, admin, idp, _) = await Setup(pg);
        using var _f = f; await using var _i = idp;
        // local user alice links the provider identity
        var alice = f.NewClient();
        Assert.True(await alice.LoginAsync("alice", "alice-new-pass-1234"));
        var page = await alice.Http.GetStringAsync("/account");
        var tok = Regex.Match(page, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var start = await alice.Http.PostAsync("/account?handler=Link&slug=mock", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = tok }));
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        Assert.Contains("prompt=login", start.Headers.Location!.Query);
        Assert.Contains("max_age=0", start.Headers.Location!.Query);
        idp.User = new IdpUser { Subject = "link-1", Username = "alice-sso", Email = "alice@example.com" };
        using var idpHttp = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var cb = (await idpHttp.GetAsync(start.Headers.Location!)).Headers.Location!;
        var done = await alice.Http.GetAsync(cb.PathAndQuery);
        Assert.Equal("/account?linked=1", done.Headers.Location!.OriginalString);
        Assert.Equal("mock", (await alice.Get("/me")).Body.GetProperty("linkedProviders")[0].GetString());

        // SSO login now lands on alice's account, not a new user
        var (c2, _) = await Browser(f, idp);
        Assert.Equal("alice", await Me(c2, "username"));
        Assert.Equal(HttpStatusCode.NoContent, (await alice.Delete("/me/links/mock")).Status);
        Assert.Empty((await alice.Get("/me")).Body.GetProperty("linkedProviders").EnumerateArray());

        // a provisioned SSO-only user has no password, so unlinking their only sign-in method is refused
        idp.User = new IdpUser { Subject = "only", Username = "only-sso", Email = "only@example.com" };
        var (c3, _) = await Browser(f, idp);
        var tokenResp = await c3.GetAsync("/api/v1/csrf");
        var csrf = System.Text.Json.JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync()).RootElement.GetProperty("token").GetString()!;
        var del = new HttpRequestMessage(HttpMethod.Delete, "/api/v1/me/links/mock"); del.Headers.Add("X-Repocuck-CSRF", csrf);
        Assert.Equal(HttpStatusCode.Conflict, (await c3.SendAsync(del)).StatusCode);
    }

    [Fact]
    public async Task Provider_admin_api_validates_hides_secrets_and_applies_without_restart()
    {
        var (f, admin, idp, pid) = await Setup(pg, withMapping: false);
        using var _f = f; await using var _i = idp;
        var list = await admin.Get("/admin/providers");
        var item = list.Body.GetProperty("items")[0];
        Assert.True(item.GetProperty("hasSecret").GetBoolean());
        Assert.DoesNotContain(MockIdp.ClientSecret, list.Body.GetRawText());
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.Post("/admin/providers", new { slug = "Bad Slug", displayName = "x", authority = idp.Issuer, clientId = "c" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.Post("/admin/providers", new { slug = "ok", displayName = "x", authority = "not a url", clientId = "c" })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.Post("/admin/providers", new { slug = "mock", displayName = "x", authority = idp.Issuer, clientId = "c" })).Status);
        var test = await admin.Post($"/admin/providers/{pid}/test");
        Assert.True(test.Body.GetProperty("ok").GetBoolean()); Assert.Equal(1, test.Body.GetProperty("jwksKeys").GetInt32()); Assert.True(test.Body.GetProperty("endSession").GetBoolean());
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Put, $"/admin/providers/{pid}/mappings", new[] { new { claimValue = "g", role = "root", priority = 0 } })).Status);

        var preview = await admin.Post($"/admin/providers/{pid}/preview", new { groups = new[] { "ops" }, mappings = new[] { new { claimValue = "ops", role = "admin", priority = 1 } } });
        Assert.Equal("admin", preview.Body.GetProperty("role").GetString());
        Assert.Equal("member", (await admin.Post($"/admin/providers/{pid}/preview", new { groups = new[] { "ops" }, mappings = Array.Empty<object>() })).Body.GetProperty("role").GetString());

        // disable -> sign-in endpoint disappears immediately; enable -> back, no restart
        var anon = f.CreateClient(new() { AllowAutoRedirect = false });
        Assert.Equal(HttpStatusCode.Redirect, (await anon.GetAsync("/auth/oidc/mock/signin")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/providers/{pid}", new { enabled = false })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync("/auth/oidc/mock/signin")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/providers/{pid}", new { enabled = true })).Status);
        Assert.Equal(HttpStatusCode.Redirect, (await anon.GetAsync("/auth/oidc/mock/signin")).StatusCode);
        Assert.Contains("Mock IdP", await anon.GetStringAsync("/login"));
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Delete($"/admin/providers/{pid}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync("/auth/oidc/mock/signin")).StatusCode);
    }

    [Theory]
    [InlineData("groups", "[\"a\",\"b\"]", "groups", "a,b")]
    [InlineData("groups", "a b", "groups", "a,b")]
    [InlineData("groups", "a,b", "groups", "a,b")]
    public void Group_claim_forms(string type, string value, string path, string expected) =>
        Assert.Equal(expected, string.Join(",", Infrastructure.Auth.ExternalLoginService.ExtractGroups([(type, value)], path)));

    [Fact]
    public void Dotted_group_claim_paths_are_supported()
    {
        var claims = new[] { ("realm_access", "{\"roles\":[\"rc-admins\",\"other\"]}") };
        Assert.Equal(["rc-admins", "other"], Infrastructure.Auth.ExternalLoginService.ExtractGroups(claims, "realm_access.roles"));
        Assert.Empty(Infrastructure.Auth.ExternalLoginService.ExtractGroups(claims, "resource_access.x"));
    }
}
