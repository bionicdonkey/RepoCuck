using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Web.Infrastructure;

namespace RepoCuck.Web.Api;

public static class SystemEndpoints
{
    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/healthz", () => Results.Json(new { status = "ok" })).AllowAnonymous();
        app.MapGet("/readyz", async (IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            try
            {
                await using var db = await dbf.CreateDbContextAsync(ct);
                return await db.Database.CanConnectAsync(ct) ? Results.Json(new { status = "ok" }) : Results.Json(new { status = "unavailable" }, statusCode: 503);
            }
            catch { return Results.Json(new { status = "unavailable" }, statusCode: 503); }
        }).AllowAnonymous();

        app.MapGet("/metrics", async (HttpContext ctx, Metrics m, IDbContextFactory<AppDbContext> dbf, IConfiguration cfg, CancellationToken ct) =>
        {
            var token = cfg["Metrics:Token"];
            var bearer = ctx.Request.Headers.Authorization.ToString();
            var ok = !string.IsNullOrEmpty(token)
                ? bearer.StartsWith("Bearer ", StringComparison.Ordinal) && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(bearer[7..]), Encoding.UTF8.GetBytes(token))
                : System.Net.IPAddress.IsLoopback(ctx.Connection.RemoteIpAddress ?? System.Net.IPAddress.None) && !ctx.Request.Headers.ContainsKey("X-Forwarded-For");
            if (!ok) return Results.NotFound();
            await using var db = await dbf.CreateDbContextAsync(ct);
            var gauges = new List<(string, double)>();
            foreach (var g in await db.Jobs.GroupBy(j => j.State).Select(g => new { g.Key, N = g.Count() }).ToListAsync(ct))
                gauges.Add(($"repocuck_jobs_queue_depth{{state=\"{g.Key}\"}}", g.N));
            foreach (var g in await db.PackageVariants.GroupBy(v => v.State).Select(g => new { g.Key, N = g.Count() }).ToListAsync(ct))
                gauges.Add(($"repocuck_package_variants{{state=\"{g.Key}\"}}", g.N));
            foreach (var g in await db.ChangeRequests.Where(r => r.Status == RequestStatus.Pending).GroupBy(r => r.Kind).Select(g => new { g.Key, N = g.Count() }).ToListAsync(ct))
                gauges.Add(($"repocuck_requests_pending{{kind=\"{g.Key}\"}}", g.N));
            var now = DateTimeOffset.UtcNow;
            foreach (var s in await (from c in db.AptCurrent join gen in db.AptGenerations on c.GenerationId equals gen.Id
                                     join su in db.AptSuites on c.SuiteId equals su.Id select new { su.Name, gen.ActivatedAt }).ToListAsync(ct))
                gauges.Add(($"repocuck_index_age_seconds{{suite=\"{s.Name}\"}}", s.ActivatedAt is null ? -1 : (now - s.ActivatedAt.Value).TotalSeconds));
            gauges.Add(("repocuck_blob_bytes", await db.Blobs.SumAsync(b => (long?)b.SizeBytes, ct) ?? 0));
            return Results.Text(m.Render(gauges), "text/plain; version=0.0.4");
        }).AllowAnonymous();

        app.MapPost("/webhooks/github", async (HttpContext ctx, IOptions<GitHubOptions> opt, IDbContextFactory<AppDbContext> dbf, JobQueue jobs, CancellationToken ct) =>
        {
            var secret = opt.Value.WebhookSecret;
            if (string.IsNullOrEmpty(secret)) return Results.NotFound();
            using var ms = new MemoryStream();
            await ctx.Request.Body.CopyToAsync(ms, ct);
            var body = ms.ToArray();
            var sig = ctx.Request.Headers["X-Hub-Signature-256"].ToString();
            var expected = "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), body));
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(sig), Encoding.ASCII.GetBytes(expected))) return Results.StatusCode(401);
            var ev = ctx.Request.Headers["X-GitHub-Event"].ToString();
            if (ev == "ping") return Results.Ok();
            if (ev != "release") return Results.Accepted();
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("repository", out var r) && r.TryGetProperty("id", out var idEl) && idEl.TryGetInt64(out var ghId))
            {
                await using var db = await dbf.CreateDbContextAsync(ct);
                var repo = await db.Repositories.AsNoTracking().FirstOrDefaultAsync(x => x.GithubRepoId == ghId && x.State == RepoState.Active, ct);
                if (repo is not null) await jobs.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = repo.Id, trigger = "webhook", reevaluate = false }, $"sync:{repo.Id}", ct: ct);
            }
            return Results.Accepted();
        }).AllowAnonymous().DisableAntiforgery();
    }
}
