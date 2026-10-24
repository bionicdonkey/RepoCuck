using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Domain;

namespace RepoCuck.Tests;

[Collection("pg")]
public class CurationTests(PostgresFixture pg)
{
    private static Task<(AppFactory F, ApiClient Admin, ApiClient Member)> Start(PostgresFixture pg, Action<AppFactory>? c = null) =>
        Scenario.StartAsync(pg, f => { f.Settings["REPOCUCK:ROLE"] = "web"; c?.Invoke(f); });

    private static async Task<Guid> AddDirect(ApiClient admin, AppFactory f, string full, string[] archs)
    {
        var p = full.Split('/');
        var (c, js) = await admin.Post("/admin/repositories", new { owner = p[0], name = p[1], architectures = archs });
        Assert.Equal(HttpStatusCode.Created, c);
        var id = js.GetProperty("id").GetGuid();
        await f.SyncAsync(id);
        return id;
    }

    [Fact]
    public async Task First_come_wins_conflict_is_visible_rearbitration_swaps_bytes_and_promotion_on_block()
    {
        var (f, admin, member) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/orig", 1); f.GitHub.AddRepo("acme/fork", 2);
        var origDeb = Scenario.Deb("tool", "1.0", "amd64", "Section: orig");
        var forkDeb = Scenario.Deb("tool", "1.0", "amd64", "Section: forked");
        f.GitHub.AddRelease(1, "v1", false, ("tool_1.0_amd64.deb", origDeb));
        f.GitHub.AddRelease(2, "v1", false, ("tool_1.0_amd64.deb", forkDeb));
        var orig = await AddDirect(admin, f, "acme/orig", ["amd64"]);
        var fork = await AddDirect(admin, f, "acme/fork", ["amd64"]);
        await f.PublishAsync();

        var idx = await f.PackagesAsync("amd64");
        Assert.Equal(1, idx.Split("Package: tool\n").Length - 1);
        Assert.Contains("Section: orig", idx);                       // first source wins
        var sha = System.Security.Cryptography.SHA256.HashData(origDeb);
        Assert.Contains("SHA256: " + Convert.ToHexStringLower(sha), idx);

        var conflicts = await admin.Get("/admin/conflicts");
        Assert.Single(conflicts.Body.GetProperty("items").EnumerateArray());
        var pk = await member.Get($"/repositories/{fork}/packages");   // visible to members
        Assert.Equal("acme/orig", pk.Body.GetProperty("items")[0].GetProperty("others")[0].GetProperty("repository").GetString());
        var runs = await member.Get($"/repositories/{fork}/sync-runs");
        Assert.Equal(1, runs.Body.GetProperty("items")[0].GetProperty("conflictsFound").GetInt32());
        Assert.False(runs.Body.GetProperty("items")[0].TryGetProperty("error", out var e) && e.ValueKind == System.Text.Json.JsonValueKind.String);

        // re-arbitration: higher priority for the fork flips the published bytes
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/repositories/{fork}", new { sourcePriority = 10 })).Status);
        var (c, js) = await admin.Post($"/admin/repositories/{fork}/rearbitrate");
        Assert.Equal(1, js.GetProperty("changed").GetInt32());
        await f.PublishAsync();
        idx = await f.PackagesAsync("amd64");
        Assert.Contains("Section: forked", idx);
        Assert.Contains("SHA256: " + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(forkDeb)), idx);
        // served file matches the index hash
        var fn = idx.Split('\n').First(l => l.StartsWith("Filename: ")).Substring(10);
        var (st, body, _) = await f.RawGet("/apt/" + fn);
        Assert.Equal(HttpStatusCode.OK, st); Assert.Equal(forkDeb, body);

        // blocking the winner promotes the other source automatically
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{fork}/block", new { reason = "x" })).Status);
        await f.PublishAsync();
        idx = await f.PackagesAsync("amd64");
        Assert.Contains("Section: orig", idx);
        Assert.Equal(1, idx.Split("Package: tool\n").Length - 1);
        var audit = await admin.Get("/admin/audit?limit=100");
        Assert.Contains(audit.Body.GetProperty("items").EnumerateArray(), i => i.GetProperty("action").GetString() == "variant.winner_changed");

        // with no alternate left the variant is tombstoned
        Assert.Equal(HttpStatusCode.OK, (await admin.Post($"/admin/repositories/{orig}/block", new { reason = "y" })).Status);
        await f.PublishAsync();
        Assert.DoesNotContain("Package: tool\n", await f.PackagesAsync("amd64"));
    }

    [Fact]
    public async Task Identical_bytes_from_two_repositories_produce_one_stanza_and_no_conflict()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        var deb = Scenario.Deb("same", "1.0", "amd64");
        f.GitHub.AddRepo("acme/a", 1); f.GitHub.AddRepo("acme/b", 2);
        f.GitHub.AddRelease(1, "v1", false, ("same_1.0_amd64.deb", deb)); f.GitHub.AddRelease(2, "v1", false, ("same_1.0_amd64.deb", deb));
        await AddDirect(admin, f, "acme/a", ["amd64"]); await AddDirect(admin, f, "acme/b", ["amd64"]);
        await f.PublishAsync();
        Assert.Equal(1, (await f.PackagesAsync("amd64")).Split("Package: same\n").Length - 1);
        Assert.Empty((await admin.Get("/admin/conflicts")).Body.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Policy_quarantines_reserved_names_epochs_and_provides_replaces_and_admin_can_release()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/evil", 1);
        f.GitHub.AddRelease(1, "v1", false,
            ("libc6_9_amd64.deb", Scenario.Deb("libc6", "9", "amd64")),
            ("epoch_1.deb", Scenario.Deb("epochpkg", "2:1.0", "amd64")),
            ("repl_1.deb", Scenario.Deb("harmless", "1.0", "amd64", "Replaces: openssh-server (<< 99)\nProvides: sudo")),
            ("ok_1.deb", Scenario.Deb("fine-pkg", "1.0", "amd64")));
        var id = await AddDirect(admin, f, "acme/evil", ["amd64"]);
        await f.PublishAsync();
        var idx = await f.PackagesAsync("amd64");
        Assert.Contains("Package: fine-pkg\n", idx);
        foreach (var bad in new[] { "libc6", "epochpkg", "harmless" }) Assert.DoesNotContain($"Package: {bad}\n", idx);
        var q = await admin.Get("/admin/quarantine");
        var items = q.Body.GetProperty("items").EnumerateArray().ToList();
        Assert.Equal(3, items.Count);
        Assert.Contains(items, i => i.GetProperty("reason").GetString() == "epoch");
        Assert.Contains(items, i => i.GetProperty("reason").GetString()!.StartsWith("reserved_name"));
        // quarantined pool files are not served
        var libc = items.First(i => i.GetProperty("package").GetString() == "libc6");
        var (st, _, _) = await f.RawGet("/apt/pool/main/libc6/libc6/libc6_9_amd64.deb");
        Assert.Equal(HttpStatusCode.NotFound, st);
        // admin releases one explicitly
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Post($"/admin/variants/{libc.GetProperty("variantId").GetGuid()}/release")).Status);
        await f.PublishAsync();
        Assert.Contains("Package: libc6\n", await f.PackagesAsync("amd64"));
        // and can quarantine something else
        var fine = await f.WithDbAsync(db => db.PackageVariants.Where(v => v.Version == "1.0" && v.State == VariantState.Active).Select(v => v.Id).FirstAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await admin.Post($"/admin/variants/{fine}/quarantine")).Status);
        await f.PublishAsync();
        Assert.DoesNotContain("Package: fine-pkg\n", await f.PackagesAsync("amd64"));
    }

    [Fact]
    public async Task Prereleases_publish_to_testing_only_and_flag_flip_moves_variant()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1.0", false, ("tool_1.0_amd64.deb", Scenario.Deb("tool", "1.0", "amd64")));
        f.GitHub.AddRelease(1, "v2.0-rc1", true, ("tool_2.0~rc1_amd64.deb", Scenario.Deb("tool", "2.0~rc1", "amd64")));
        var id = await AddDirect(admin, f, "acme/tool", ["amd64"]);
        await f.PublishAsync();
        Assert.DoesNotContain("2.0~rc1", await f.PackagesAsync("amd64"));                // prereleases ignored by default
        Assert.Equal(HttpStatusCode.OK, (await admin.Patch($"/admin/repositories/{id}", new { includePrereleases = true })).Status);
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.DoesNotContain("2.0~rc1", await f.PackagesAsync("amd64"));                // not in stable
        var testing = await f.PackagesAsync("amd64", "testing");
        Assert.Contains("Version: 2.0~rc1", testing); Assert.Contains("Version: 1.0", testing);
        var (_, rel, _) = await f.RawGet("/apt/dists/testing/Release");
        Assert.Contains("NotAutomatic: yes", Encoding.UTF8.GetString(rel));
        // upstream promotes the prerelease to a full release -> appears in stable
        f.GitHub.SetPrerelease(1, "v2.0-rc1", false);
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.Contains("Version: 2.0~rc1", await f.PackagesAsync("amd64"));
    }

    [Fact]
    public async Task Holdback_delays_publication()
    {
        var (f, admin, _) = await Start(pg);
        using var _ = f;
        f.GitHub.AddRepo("acme/tool", 1);
        f.GitHub.AddRelease(1, "v1.0", false, ("tool_1.0_amd64.deb", Scenario.Deb("tool", "1.0", "amd64")));
        var (_, js) = await admin.Post("/admin/repositories", new { owner = "acme", name = "tool", architectures = new[] { "amd64" } });
        var id = js.GetProperty("id").GetGuid();
        await admin.Patch($"/admin/repositories/{id}", new { holdbackHours = 24 });
        await f.SyncAsync(id); await f.PublishAsync();
        Assert.DoesNotContain("Package: tool\n", await f.PackagesAsync("amd64"));
        await f.WithDbAsync(async db => { await db.PackageVariants.ExecuteUpdateAsync(s => s.SetProperty(v => v.PublishAfter, DateTimeOffset.UtcNow.AddMinutes(-1))); return 0; });
        await f.PublishAsync();
        Assert.Contains("Package: tool\n", await f.PackagesAsync("amd64"));
    }
}
