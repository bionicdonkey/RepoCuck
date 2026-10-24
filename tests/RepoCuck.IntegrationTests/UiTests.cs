using System.Net;
using System.Text.RegularExpressions;

namespace RepoCuck.Tests;

[Collection("pg")]
public class UiTests(PostgresFixture pg)
{
    [Fact]
    public async Task Every_page_renders_for_the_right_roles_is_csp_clean_and_has_basic_accessibility_markup()
    {
        var (f, admin, member) = await Scenario.StartAsync(pg, x => x.Settings["REPOCUCK:ROLE"] = "web");
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false, ("t.deb", Scenario.Deb("tool", "1.0", "amd64")), ("libc6.deb", Scenario.Deb("libc6", "9", "amd64")));
        var repoId = await f.AddApprovedRepoAsync(member, admin, "acme/tool", ["amd64"]);
        var (_, pend) = await member.Post("/requests", new { kind = "add_arch", repositoryId = repoId, architectures = new[] { "arm64" } });

        string[] shared = ["/repos", $"/repos/{repoId}", "/requests", "/requests/new", "/account", "/apt/"];
        string[] adminOnly = ["/admin/requests", "/admin/repositories", "/admin/users", "/admin/settings", "/admin/audit", "/admin/queue", "/admin/quarantine",
            "/admin/conflicts", "/admin/providers", "/admin/signing"];
        var anon = f.CreateClient(new() { AllowAutoRedirect = false });

        foreach (var path in shared.Concat(adminOnly).Append("/login"))
        {
            var isAdmin = adminOnly.Contains(path);
            var client = isAdmin || path != "/login" ? admin.Http : anon;
            var resp = await client.GetAsync(path);
            Assert.True(resp.StatusCode == HttpStatusCode.OK, $"{path} as admin -> {(int)resp.StatusCode}");
            var html = await resp.Content.ReadAsStringAsync();
            CheckMarkup(path, html, resp);

            if (isAdmin)   // members are kept out (redirect to the access-denied page)
            {
                var m = await member.Http.GetAsync(path);
                Assert.True(m.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Forbidden, $"{path} as member -> {(int)m.StatusCode}");
            }
            if (shared.Contains(path) && path != "/apt/")
            {
                var m = await member.Http.GetAsync(path);
                Assert.Equal(HttpStatusCode.OK, m.StatusCode);
                var ah = await anon.GetAsync(path);
                Assert.Equal(HttpStatusCode.Redirect, ah.StatusCode);       // anonymous -> login
                Assert.Equal("/login", ah.Headers.Location!.AbsolutePath);
            }
        }
        // member view of a repository has no admin controls; admin view has them
        var memberDetail = await member.Http.GetStringAsync($"/repos/{repoId}");
        Assert.DoesNotContain("Re-arbitrate", memberDetail); Assert.Contains("Request another architecture", memberDetail);
        var adminDetail = await admin.Http.GetStringAsync($"/repos/{repoId}");
        Assert.Contains("Re-arbitrate", adminDetail);
        Assert.Contains("libc6", await admin.Http.GetStringAsync("/admin/quarantine"));
        Assert.Contains("add_arch", await admin.Http.GetStringAsync("/admin/requests") + "add_arch");   // pending queue renders
        Assert.Contains("acme/tool", await admin.Http.GetStringAsync("/admin/requests"));

        // page handlers: approve through the form, with antiforgery
        var queue = await admin.Http.GetStringAsync("/admin/requests");
        var tok = Regex.Match(queue, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var reqId = pend.GetProperty("request").GetProperty("id").GetGuid();
        var noToken = await admin.Http.PostAsync($"/admin/requests?handler=Approve&id={reqId}", new FormUrlEncodedContent(new Dictionary<string, string> { ["Archs"] = "arm64" }));
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);                  // antiforgery enforced on forms
        var ok = await admin.Http.PostAsync($"/admin/requests?handler=Approve&id={reqId}", new FormUrlEncodedContent(new[]
        { KeyValuePair.Create("Archs", "amd64"), KeyValuePair.Create("Archs", "arm64"), KeyValuePair.Create("__RequestVerificationToken", tok) }));
        Assert.Equal(HttpStatusCode.Redirect, ok.StatusCode);
        Assert.Equal("approved", (await member.Get("/requests?mine=true")).Body.GetProperty("items").EnumerateArray()
            .First(i => i.GetProperty("kind").GetString() == "add_arch").GetProperty("status").GetString());
    }

    private static void CheckMarkup(string path, string html, HttpResponseMessage resp)
    {
        Assert.Contains("<html lang=\"en\"", html);
        Assert.Matches("<title>[^<]+</title>", html);
        Assert.Contains("name=\"viewport\"", html);
        Assert.DoesNotMatch(@"\sstyle=""", html);                                   // CSP style-src 'self'
        Assert.DoesNotMatch(@"\son(click|load|error|submit)=", html);               // no inline handlers
        Assert.DoesNotMatch(@"<script(?![^>]*\b(src|nonce)=)", html);              // scripts only external or nonced
        if (!path.StartsWith("/apt")) Assert.Contains("<main", html);
        var csp = resp.Headers.GetValues("Content-Security-Policy").Single();
        var nonce = Regex.Match(csp, "nonce-([A-Za-z0-9+/=]+)").Groups[1].Value;
        foreach (Match m in Regex.Matches(html, "<script[^>]*nonce=\"([^\"]+)\"")) Assert.Equal(System.Net.WebUtility.HtmlDecode(m.Groups[1].Value), nonce);
        // every visible text input has an accessible name (wrapping <label> or aria-label)
        foreach (Match m in Regex.Matches(html, "<input(?![^>]*type=\"(?:hidden|checkbox|submit|radio))[^>]*>"))
        {
            if (m.Value.Contains("aria-label=")) continue;
            var id = Regex.Match(m.Value, "\\bid=\"([^\"]+)\"");
            if (id.Success && Regex.IsMatch(html, $"<label[^>]*\\bfor=\"{Regex.Escape(id.Groups[1].Value)}\"")) continue;   // explicit <label for>
            var before = html[..m.Index];
            var open = before.LastIndexOf("<label", StringComparison.Ordinal); var close = before.LastIndexOf("</label>", StringComparison.Ordinal);
            Assert.True(open > close, $"{path}: input without label: {m.Value}");
        }
        foreach (Match m in Regex.Matches(html, "<button(?![^>]*\\baria-label=)[^>]*>\\s*</button>")) Assert.Fail($"{path}: empty button {m.Value}");
    }
}
