using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Services;

namespace RepoCuck.Tests;

[Collection("pg")]
public class RequestAndPublishTests(PostgresFixture pg)
{
    private static Task<(AppFactory F, ApiClient Admin, ApiClient Member)> Start(PostgresFixture pg, Action<AppFactory>? c = null) =>
        Scenario.StartAsync(pg, f => { f.Settings["REPOCUCK:ROLE"] = "web"; c?.Invoke(f); });

    [Fact]
    public async Task Request_lifecycle_nothing_published_until_approved()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false, ("tool_1.0_amd64.deb", Scenario.Deb("tool", "1.0", "amd64")), ("tool_1.0_arm64.deb", Scenario.Deb("tool", "1.0", "arm64")));

        var (c, js) = await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "tool", architectures = new[] { "amd64" }, note = "please" });
        Assert.Equal(HttpStatusCode.Created, c);
        var repoId = js.GetProperty("repository").GetProperty("id").GetGuid();
        var reqId = js.GetProperty("request").GetProperty("id").GetGuid();
        Assert.Equal("proposed", js.GetProperty("repository").GetProperty("state").GetString());

        await f.SyncAsync(repoId, "quarantine");
        await f.PublishAsync();
        Assert.DoesNotContain("tool", await f.PackagesAsync("amd64"));   // proposed: inspected but never published
        var pk = await member.Get($"/repositories/{repoId}/packages");
        Assert.Single(pk.Body.GetProperty("items").EnumerateArray());      // members can see the inspection result
        var (_, release, _) = await f.RawGet("/apt/dists/stable/Release");
        Assert.DoesNotContain("amd64", Encoding.UTF8.GetString(release).Split('\n').First(l => l.StartsWith("Architectures")));

        Assert.Equal(HttpStatusCode.Forbidden, (await member.Post($"/admin/requests/{reqId}/approve")).Status);
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/requests/{reqId}/approve", new { })).Status);
        await f.SyncAsync(repoId); await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));
        Assert.Equal("", await f.PackagesAsync("arm64"));                 // arm64 not selected for this repo
        var (st, rel2, _) = await f.RawGet("/apt/dists/stable/Release");
        Assert.Contains("Architectures: all amd64\n", Encoding.UTF8.GetString(rel2));

        var mine = await member.Get("/requests?mine=true");
        Assert.Equal("approved", mine.Body.GetProperty("items")[0].GetProperty("status").GetString());
    }

    [Fact]
    public async Task Duplicate_blocked_rejected_and_limit_behaviour()
    {
        var (f, admin, member) = await Start(pg, x => x.Settings["Limits:PendingRequestsPerUser"] = "3");
        using var _ = f;
        for (var i = 1; i <= 4; i++) f.GitHub.AddRepo($"acme/r{i}", i);

        var (c1, j1) = await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r1", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Created, c1);
        var repo1 = j1.GetProperty("repository").GetProperty("id").GetGuid();
        var (c2, j2) = await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r1", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Conflict, c2); Assert.Equal("request_pending", j2.GetProperty("code").GetString());
        var (c3, j3) = await admin.Post("/requests", new { kind = "add_repo", owner = "ACME", name = "R1", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Conflict, c3); Assert.Equal("already_watched", j3.GetProperty("code").GetString());
        Assert.Equal(repo1, j3.GetProperty("repositoryId").GetGuid());
        Assert.Equal(HttpStatusCode.NotFound, (await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "ghost", architectures = new[] { "amd64" } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r2", architectures = new[] { "sparc" } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await member.Post("/requests", new { kind = "add_repo", url = "not a repo", architectures = new[] { "amd64" } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await member.Post("/requests", new { kind = "add_repo", url = "git@github.com:acme/r2.git", architectures = new[] { "amd64" } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r3", architectures = new[] { "amd64" } })).Status);
        var (c4, j4) = await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r4", architectures = new[] { "amd64" } });
        Assert.Equal((HttpStatusCode)422, c4); Assert.Equal("request_limit", j4.GetProperty("code").GetString());

        // reject -> repository rejected with reason visible to everyone; can be re-requested
        var reqs = await admin.Get("/admin/requests");
        var r1req = reqs.Body.GetProperty("items").EnumerateArray().First(g => g.GetProperty("repositoryId").GetGuid() == repo1).GetProperty("requests")[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.Post($"/admin/requests/{r1req}/reject", new { reason = "" })).Status);
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/requests/{r1req}/reject", new { reason = "not now" })).Status);
        var detail = await member.Get($"/repositories/{repo1}");
        Assert.Equal("rejected", detail.Body.GetProperty("state").GetString()); Assert.Equal("not now", detail.Body.GetProperty("stateReason").GetString());
        Assert.Equal(HttpStatusCode.Created, (await member.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r1", architectures = new[] { "arm64" } })).Status);
        Assert.Equal("proposed", (await member.Get($"/repositories/{repo1}")).Body.GetProperty("state").GetString());

        // block -> cannot be requested; pending requests are closed
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{repo1}/block", new { reason = "policy" })).Status);
        var (c5, j5) = await admin.Post("/requests", new { kind = "add_repo", owner = "acme", name = "r1", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Forbidden, c5); Assert.Equal("repository_blocked", j5.GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{repo1}/unblock")).Status);
        Assert.Equal("proposed", (await member.Get($"/repositories/{repo1}")).Body.GetProperty("state").GetString());
    }

    [Fact]
    public async Task Cancel_rules_and_arch_requests()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false, ("tool_1.0_amd64.deb", Scenario.Deb("tool", "1.0", "amd64")), ("tool_1.0_arm64.deb", Scenario.Deb("tool", "1.0", "arm64")));
        var repoId = await f.AddApprovedRepoAsync(member, admin, "acme/tool", ["amd64"]);

        // arch requests
        Assert.Equal("already_enabled", (await member.Post("/requests", new { kind = "add_arch", repositoryId = repoId, architectures = new[] { "amd64" } })).Body.GetProperty("code").GetString());
        var (c, js) = await member.Post("/requests", new { kind = "add_arch", repositoryId = repoId, architectures = new[] { "arm64" } });
        Assert.Equal(HttpStatusCode.Created, c);
        var reqId = js.GetProperty("request").GetProperty("id").GetGuid();
        Assert.Equal("request_pending", (await member.Post("/requests", new { kind = "add_arch", repositoryId = repoId, architectures = new[] { "arm64" } })).Body.GetProperty("code").GetString());

        // another member cannot cancel it; the requester can
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Post("/admin/users", new { username = "bob", password = "bob-initial-pass-12", role = "member" })).Status == HttpStatusCode.Created ? HttpStatusCode.NoContent : HttpStatusCode.BadRequest);
        var bob = f.NewClient(); Assert.True(await bob.LoginAsync("bob", "bob-initial-pass-12"));
        await bob.Post("/me/password", new { current = "bob-initial-pass-12", newPassword = "bob-new-pass-12345" });
        bob = f.NewClient(); Assert.True(await bob.LoginAsync("bob", "bob-new-pass-12345"));
        Assert.Equal(HttpStatusCode.Forbidden, (await bob.Delete($"/requests/{reqId}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await bob.Get($"/requests/{reqId}")).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await member.Delete($"/requests/{reqId}")).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await member.Delete($"/requests/{reqId}")).Status);

        // new request, approve with override, check per-repo architecture publication
        var (_, js2) = await member.Post("/requests", new { kind = "add_arch", repositoryId = repoId, architectures = new[] { "arm64" } });
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/requests/{js2.GetProperty("request").GetProperty("id").GetGuid()}/approve", new { })).Status);
        await f.SyncAsync(repoId, reeval: true); await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("arm64"));
        Assert.Equal(HttpStatusCode.Created, (await member.Post("/requests", new { kind = "add_arch", repositoryId = repoId, architectures = new[] { "riscv64" } })).Status);
    }

    [Fact]
    public async Task Architectures_are_enforced_per_repository_not_globally()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/x", 1); f.GitHub.AddRepo("acme/y", 2);
        f.GitHub.AddRelease(1, "v1", false, ("xtool_1_amd64.deb", Scenario.Deb("xtool", "1", "amd64")), ("xtool_1_arm64.deb", Scenario.Deb("xtool", "1", "arm64")), ("xdata_1_all.deb", Scenario.Deb("xdata", "1", "all")));
        f.GitHub.AddRelease(2, "v1", false, ("ytool_1_amd64.deb", Scenario.Deb("ytool", "1", "amd64")), ("ytool_1_arm64.deb", Scenario.Deb("ytool", "1", "arm64")));
        await f.AddApprovedRepoAsync(member, admin, "acme/x", ["amd64"], publish: false);
        await f.AddApprovedRepoAsync(member, admin, "acme/y", ["arm64"], publish: false);
        foreach (var id in await f.WithDbAsync(db => db.Repositories.Select(r => r.Id).ToListAsync())) await f.SyncAsync(id);
        await f.PublishAsync();
        var amd64 = await f.PackagesAsync("amd64"); var arm64 = await f.PackagesAsync("arm64");
        Assert.Contains("Package: xtool\n", amd64); Assert.DoesNotContain("ytool", amd64);
        Assert.Contains("Package: ytool\n", arm64); Assert.DoesNotContain("xtool", arm64);    // x did not select arm64
        Assert.Contains("Package: xdata\n", amd64); Assert.Contains("Package: xdata\n", arm64);  // arch:all goes everywhere
        Assert.Contains("Package: xdata\n", await f.PackagesAsync("all"));
    }

    [Fact]
    public async Task Admin_can_add_directly_and_pause_remove_with_grace()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false, ("tool_1.0_amd64.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (c, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        Assert.Equal(HttpStatusCode.Created, c);
        var id = js.GetProperty("id").GetGuid();
        Assert.Equal("already_watched", (await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } })).Body.GetProperty("code").GetString());
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));

        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{id}/pause")).Status);
        await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));       // paused repos stay published
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{id}/resume")).Status);
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{id}/remove", new { reason = "obsolete" })).Status);
        await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));       // removed: kept during the orphan grace period
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{id}/block", new { reason = "gone" })).Status);
        await f.PublishAsync();
        Assert.DoesNotContain("Package: tool\n", await f.PackagesAsync("amd64")); // blocked: gone immediately
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Post($"/admin/repositories/{id}/unblock")).Status);
    }

    [Fact]
    public async Task Disabling_a_user_does_not_unpublish_their_repositories()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1", false, ("tool_1.0_amd64.deb", Scenario.Deb("tool", "1.0", "amd64")));
        await f.AddApprovedRepoAsync(member, admin, "acme/tool", ["amd64"]);
        var users = await admin.Get("/admin/users");
        var alice = users.Body.GetProperty("items").EnumerateArray().First(u => u.GetProperty("username").GetString() == "alice").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/users/{alice}", new { isActive = false })).Status);
        await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));
        Assert.False(await f.NewClient().LoginAsync("alice", "alice-new-pass-1234"));
    }
}
