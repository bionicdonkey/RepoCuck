using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Auth;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Web.Infrastructure;

namespace RepoCuck.Web.Api;

public sealed record PasswordBody(string? Current, string NewPassword);
public sealed record PasswordOnly(string Password);
public sealed record CodeBody(string Code);
public sealed record CreateRequestBody(string Kind, string? Owner, string? Name, string? Url, Guid? RepositoryId, string[]? Architectures, string? Note);

public static class CoreApi
{
    public static object Page<T>(IReadOnlyList<T> items, int offset, int limit) =>
        new { items = items.Take(limit), nextCursor = items.Count > limit ? (offset + limit).ToString() : null };

    private static (int Offset, int Limit) Paging(string? cursor, int? limit) =>
        (int.TryParse(cursor, out var o) && o >= 0 ? o : 0, Math.Clamp(limit ?? 25, 1, 100));

    public static void MapCoreApi(this RouteGroupBuilder api)
    {
        api.MapGet("/csrf", (HttpContext ctx, IAntiforgery af) => Results.Json(new { token = af.GetAndStoreTokens(ctx).RequestToken, header = ApiCsrfMiddleware.HeaderName }));

        // ---- profile ----
        api.MapGet("/me", async (HttpContext ctx, UserService users, CancellationToken ct) =>
        {
            var u = await users.FindAsync(ctx.User.RequireId(), ct) ?? throw new ServiceException("unauthenticated", "Sign in required.", 401);
            return Results.Json(new { u.Id, u.Username, u.DisplayName, u.Email, u.Role, totpEnabled = u.TotpEnabled, mustChangePassword = u.MustChangePassword, linkedProviders = Array.Empty<string>() });
        });
        api.MapPost("/me/password", async (HttpContext ctx, PasswordBody b, UserService users, CancellationToken ct) =>
        {
            await users.ChangePasswordAsync(ctx.User.RequireId(), b.Current, b.NewPassword, false, ct);
            return Results.NoContent();
        });
        api.MapPost("/me/totp/enable", async (HttpContext ctx, PasswordOnly b, UserService users, CancellationToken ct) =>
        {
            var (secret, uri) = await users.BeginTotpAsync(ctx.User.RequireId(), b.Password, ct);
            return Results.Json(new { secret, otpauthUri = uri });
        });
        api.MapPost("/me/totp/confirm", async (HttpContext ctx, CodeBody b, UserService users, CancellationToken ct) =>
            Results.Json(new { recoveryCodes = await users.ConfirmTotpAsync(ctx.User.RequireId(), b.Code, ct) }));
        api.MapPost("/me/totp/disable", async (HttpContext ctx, PasswordOnly b, UserService users, CancellationToken ct) =>
        {
            await users.DisableTotpAsync(ctx.User.RequireId(), b.Password, ct);
            return Results.NoContent();
        });
        api.MapPost("/me/sessions/revoke-all", async (HttpContext ctx, UserService users, CancellationToken ct) =>
        {
            await users.RevokeSessionsAsync(ctx.User.RequireId(), ct);
            return Results.NoContent();
        });

        // ---- repositories (read) ----
        api.MapGet("/repositories", async (IDbContextFactory<AppDbContext> dbf, string? state, string? q, string? cursor, int? limit, CancellationToken ct) =>
        {
            var (offset, lim) = Paging(cursor, limit);
            await using var db = await dbf.CreateDbContextAsync(ct);
            var rq = db.Repositories.AsNoTracking().AsQueryable();
            if (!string.IsNullOrEmpty(state)) rq = rq.Where(r => r.State == state);
            if (!string.IsNullOrWhiteSpace(q)) { var like = "%" + q.Trim().Replace("%", "").Replace("_", "") + "%"; rq = rq.Where(r => EF.Functions.ILike(r.FullName, like)); }
            var rows = await rq.OrderBy(r => r.FullName).Skip(offset).Take(lim + 1).Select(r => new
            {
                r.Id, githubId = r.GithubRepoId, r.FullName, r.HtmlUrl, r.Description, r.State, r.StateReason, r.Architectures, r.IncludePrereleases,
                r.HoldbackHours, r.IsArchived, r.LastSyncedAt, r.LastSyncStatus, r.CreatedAt,
                packageCount = db.PackageSources.Count(s => s.RepositoryId == r.Id && s.IsWinner),
                stale = r.ConsecutiveFailures >= 5
            }).ToListAsync(ct);
            return Results.Json(Page(rows, offset, lim));
        });

        api.MapGet("/repositories/{id:guid}", async (Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var r = await db.Repositories.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new ServiceException("not_found", "Repository not found.", 404);
            var proposer = r.ProposedBy is null ? null : await db.Users.Where(u => u.Id == r.ProposedBy).Select(u => u.DisplayName).FirstOrDefaultAsync(ct);
            var last = await db.SyncRuns.AsNoTracking().Where(s => s.RepositoryId == id).OrderByDescending(s => s.StartedAt).Select(s => new { s.Status, s.StartedAt, s.FinishedAt, s.ErrorCategory }).FirstOrDefaultAsync(ct);
            return Results.Json(new
            {
                r.Id, githubId = r.GithubRepoId, r.Owner, r.Name, r.FullName, r.HtmlUrl, r.Description, r.Notes, license = r.LicenseSpdx, r.DefaultBranch,
                r.IsArchived, r.State, r.StateReason, r.Architectures, r.SourcePriority, r.IncludePrereleases, r.HoldbackHours, r.AssetIncludeGlob,
                r.AssetExcludeGlob, r.MaxAssetBytes, r.SyncIntervalMinutes, r.NextSyncAt, r.LastSyncedAt, r.LastSyncStatus, stale = r.ConsecutiveFailures >= 5,
                requestedBy = proposer, r.CreatedAt, r.ApprovedAt, lastSync = last
            });
        });

        api.MapGet("/repositories/{id:guid}/packages", async (Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            if (!await db.Repositories.AnyAsync(r => r.Id == id, ct)) throw new ServiceException("not_found", "Repository not found.", 404);
            var rows = await (from s in db.PackageSources.AsNoTracking()
                              join v in db.PackageVariants.AsNoTracking() on s.VariantId equals v.Id
                              join p in db.Packages.AsNoTracking() on v.PackageId equals p.Id
                              where s.RepositoryId == id
                              orderby p.Name, v.Version
                              select new
                              {
                                  variantId = v.Id, package = p.Name, v.Version, v.Architecture, v.Channel, v.State, v.QuarantineReason, v.Filename, v.SizeBytes, v.Sha256,
                                  v.PublishAfter, v.PublishedAt, isWinner = s.IsWinner,
                                  others = db.PackageSources.Where(o => o.VariantId == v.Id && o.Id != s.Id)
                                      .Join(db.Repositories, o => o.RepositoryId, r => r.Id, (o, r) => new { repository = r.FullName, identical = o.BlobId == s.BlobId, winner = o.IsWinner }).ToList()
                              }).Take(2000).ToListAsync(ct);
            return Results.Json(new { items = rows });
        });

        api.MapGet("/repositories/{id:guid}/releases", async (Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            if (!await db.Repositories.AnyAsync(r => r.Id == id, ct)) throw new ServiceException("not_found", "Repository not found.", 404);
            var rels = await db.Releases.AsNoTracking().Where(r => r.RepositoryId == id).OrderByDescending(r => r.PublishedAt).Take(50).ToListAsync(ct);
            var ids = rels.Select(r => r.Id).ToList();
            var assets = await db.ReleaseAssets.AsNoTracking().Where(a => ids.Contains(a.ReleaseId)).ToListAsync(ct);
            return Results.Json(new
            {
                items = rels.Select(r => new
                {
                    r.Id, r.TagName, r.Name, r.IsPrerelease, r.PublishedAt, r.HtmlUrl,
                    assets = assets.Where(a => a.ReleaseId == r.Id).Select(a => new { a.Name, a.SizeBytes, a.State, reason = a.ExcludedReason ?? a.FailureReason, a.DownloadCount, noUpstreamDigest = a.DigestSha256 == null })
                })
            });
        });

        api.MapGet("/repositories/{id:guid}/sync-runs", async (HttpContext ctx, Guid id, IDbContextFactory<AppDbContext> dbf, string? cursor, int? limit, CancellationToken ct) =>
        {
            var (offset, lim) = Paging(cursor, limit);
            var admin = ctx.User.IsAdmin();
            await using var db = await dbf.CreateDbContextAsync(ct);
            if (!await db.Repositories.AnyAsync(r => r.Id == id, ct)) throw new ServiceException("not_found", "Repository not found.", 404);
            var rows = await db.SyncRuns.AsNoTracking().Where(s => s.RepositoryId == id).OrderByDescending(s => s.StartedAt).Skip(offset).Take(lim + 1)
                .Select(s => new
                {
                    s.Id, s.Trigger, s.StartedAt, s.FinishedAt, s.Status, s.ReleasesSeen, s.AssetsSeen, s.AssetsIngested, s.AssetsExcluded, s.AssetsFailed,
                    s.VariantsCreated, s.ConflictsFound, s.ErrorCategory, error = admin ? s.Error : null
                }).ToListAsync(ct);
            return Results.Json(Page(rows, offset, lim));
        });

        api.MapGet("/repositories/{id:guid}/requests", async (Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var rows = await RequestQuery(db, r => r.RepositoryId == id).OrderByDescending(x => x.CreatedAt).Take(100).ToListAsync(ct);
            return Results.Json(new { items = rows });
        });

        // ---- requests ----
        api.MapGet("/requests", async (HttpContext ctx, IDbContextFactory<AppDbContext> dbf, bool? mine, string? status, string? cursor, int? limit, CancellationToken ct) =>
        {
            var (offset, lim) = Paging(cursor, limit);
            var wantMine = mine ?? true;
            if (!wantMine && !ctx.User.IsAdmin()) throw new ServiceException("forbidden", "Admin role required.", 403);
            var uid = ctx.User.RequireId();
            await using var db = await dbf.CreateDbContextAsync(ct);
            var q = RequestQuery(db, r => (!wantMine || r.RequestedBy == uid) && (string.IsNullOrEmpty(status) || r.Status == status));
            var rows = await q.OrderByDescending(x => x.CreatedAt).Skip(offset).Take(lim + 1).ToListAsync(ct);
            return Results.Json(Page(rows, offset, lim));
        });
        api.MapGet("/requests/{id:guid}", async (HttpContext ctx, Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var r = await RequestQuery(db, c => c.Id == id).FirstOrDefaultAsync(ct) ?? throw new ServiceException("not_found", "Request not found.", 404);
            if (r.RequestedById != ctx.User.RequireId() && !ctx.User.IsAdmin()) throw new ServiceException("forbidden", "Not your request.", 403);
            return Results.Json(r);
        });
        api.MapPost("/requests", async (HttpContext ctx, CreateRequestBody b, RequestService svc, CancellationToken ct) =>
        {
            var res = await svc.CreateAsync(ctx.User.RequireId(), new CreateRequestInput(b.Kind, b.Owner, b.Name, b.Url, b.RepositoryId, b.Architectures, b.Note), ct);
            ctx.Response.Headers.Location = $"/api/v1/requests/{res.Request.Id}";
            return Results.Json(new
            {
                request = new { res.Request.Id, res.Request.Kind, res.Request.Status, res.Request.Architectures, res.Request.Note, res.Request.CreatedAt },
                repository = new { res.Repository.Id, res.Repository.FullName, res.Repository.State }
            }, statusCode: 201);
        });
        api.MapDelete("/requests/{id:guid}", async (HttpContext ctx, Guid id, RequestService svc, CancellationToken ct) =>
        {
            await svc.CancelAsync(id, ctx.User.RequireId(), ctx.User.IsAdmin(), ct);
            return Results.NoContent();
        });
    }

    public sealed class RequestRow
    {
        public Guid Id { get; set; }
        public string Kind { get; set; } = "";
        public Guid RepositoryId { get; set; }
        public string RepositoryName { get; set; } = "";
        public string RepositoryState { get; set; } = "";
        public Guid RequestedById { get; set; }
        public string RequestedBy { get; set; } = "";
        public string[] Architectures { get; set; } = [];
        public string? Note { get; set; }
        public string Status { get; set; } = "";
        public string? DecisionNote { get; set; }
        public DateTimeOffset? DecidedAt { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }

    public static IQueryable<RequestRow> RequestQuery(AppDbContext db, System.Linq.Expressions.Expression<Func<ChangeRequest, bool>>? pred = null) =>
        from r in (pred is null ? db.ChangeRequests.AsNoTracking() : db.ChangeRequests.AsNoTracking().Where(pred))
        join repo in db.Repositories.AsNoTracking() on r.RepositoryId equals repo.Id
        join u in db.Users.AsNoTracking() on r.RequestedBy equals u.Id
        select new RequestRow
        {
            Id = r.Id, Kind = r.Kind, RepositoryId = repo.Id, RepositoryName = repo.FullName, RepositoryState = repo.State, RequestedById = u.Id,
            RequestedBy = u.DisplayName, Architectures = r.Architectures, Note = r.Note, Status = r.Status, DecisionNote = r.DecisionNote,
            DecidedAt = r.DecidedAt, CreatedAt = r.CreatedAt
        };
}
