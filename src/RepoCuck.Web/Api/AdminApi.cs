using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Auth;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Web.Infrastructure;

namespace RepoCuck.Web.Api;

public sealed record ApproveBody(string[]? Architectures, bool? IncludePrereleases, int? HoldbackHours, string? Note);
public sealed record RejectBody(string? Reason);
public sealed record AddRepoBody(string? Owner, string? Name, string? Url, string[]? Architectures);
public sealed record ReasonBody(string? Reason);
public sealed record SyncBody(bool Reevaluate);
public sealed record CreateUserBody(string Username, string? DisplayName, string? Email, string? Password, string? Role);
public sealed record UpdateUserBody(string? Role, bool? IsActive, string? DisplayName);
public sealed record SettingsBody(string[]? ArchAllowList, string[]? ReservedNames);

public static class AdminApi
{
    public static void MapAdminApi(this RouteGroupBuilder api)
    {
        var a = api.MapGroup("/admin").RequireAuthorization("Admin");

        // ---- requests ----
        a.MapGet("/requests", async (IDbContextFactory<AppDbContext> dbf, string? status, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var rows = await CoreApi.RequestQuery(db, r => r.Status == (status ?? RequestStatus.Pending)).OrderBy(x => x.CreatedAt).Take(500).ToListAsync(ct);
            return Results.Json(new { items = rows.GroupBy(r => r.RepositoryId).Select(g => new { repositoryId = g.Key, repository = g.First().RepositoryName, requests = g }) });
        });
        a.MapPost("/requests/{id:guid}/approve", async (HttpContext ctx, Guid id, ApproveBody? b, RequestService svc, CancellationToken ct) =>
        {
            var r = await svc.ApproveAsync(id, ctx.User.RequireId(), b is null ? null : new ApproveOverrides(b.Architectures, b.IncludePrereleases, b.HoldbackHours, b.Note), ct);
            return Results.Json(new { r.Id, r.Status });
        });
        a.MapPost("/requests/{id:guid}/reject", async (HttpContext ctx, Guid id, RejectBody b, RequestService svc, CancellationToken ct) =>
        {
            var r = await svc.RejectAsync(id, ctx.User.RequireId(), b.Reason, ct);
            return Results.Json(new { r.Id, r.Status });
        });

        // ---- repositories ----
        a.MapPost("/repositories", async (HttpContext ctx, AddRepoBody b, RepositoryAdminService svc, CancellationToken ct) =>
        {
            var r = await svc.AddDirectAsync(ctx.User.RequireId(), b.Owner, b.Name, b.Url, b.Architectures, ct);
            return Results.Json(new { r.Id, r.FullName, r.State, r.Architectures }, statusCode: 201);
        });
        a.MapPatch("/repositories/{id:guid}", async (HttpContext ctx, Guid id, RepoPatch p, RepositoryAdminService svc, CancellationToken ct) =>
        {
            var r = await svc.PatchAsync(id, ctx.User.RequireId(), p, ct);
            return Results.Json(new { r.Id, r.State, r.Architectures });
        });
        foreach (var action in new[] { "pause", "resume", "remove", "block", "unblock", "reinstate" })
            a.MapPost($"/repositories/{{id:guid}}/{action}", async (HttpContext ctx, Guid id, ReasonBody? b, RepositoryAdminService svc, CancellationToken ct) =>
            {
                var r = await svc.SetStateAsync(id, ctx.User.RequireId(), action, b?.Reason, ct);
                return Results.Json(new { r.Id, r.State });
            });
        a.MapPost("/repositories/{id:guid}/sync", async (HttpContext ctx, Guid id, SyncBody? b, RepositoryAdminService svc, CancellationToken ct) =>
        {
            await svc.EnqueueSyncAsync(id, ctx.User.RequireId(), b?.Reevaluate ?? false, ct);
            return Results.Accepted();
        });
        a.MapPost("/repositories/{id:guid}/rearbitrate", async (HttpContext ctx, Guid id, RepositoryAdminService svc, CancellationToken ct) =>
            Results.Json(new { changed = await svc.RearbitrateAsync(id, ctx.User.RequireId(), ct) }));

        // ---- users ----
        a.MapGet("/users", async (IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            return Results.Json(new
            {
                items = await db.Users.AsNoTracking().OrderBy(u => u.Username).Select(u => new
                { u.Id, u.Username, u.DisplayName, u.Email, u.Role, u.RoleLocked, u.IsActive, u.TotpEnabled, u.MustChangePassword, u.LastLoginAt, u.CreatedAt }).ToListAsync(ct)
            });
        });
        a.MapPost("/users", async (HttpContext ctx, CreateUserBody b, UserService users, CancellationToken ct) =>
        {
            var u = await users.CreateAsync(b.Username, b.DisplayName ?? b.Username, b.Email, b.Password, b.Role ?? Roles.Member, true, ctx.User.RequireId(), ct);
            return Results.Json(new { u.Id, u.Username, u.Role }, statusCode: 201);
        });
        a.MapPatch("/users/{id:guid}", async (HttpContext ctx, Guid id, UpdateUserBody b, UserService users, CancellationToken ct) =>
        {
            var u = await users.UpdateAsync(id, ctx.User.RequireId(), b.Role, b.IsActive, b.DisplayName, ct);
            return Results.Json(new { u.Id, u.Role, u.IsActive });
        });
        a.MapDelete("/users/{id:guid}", async (HttpContext ctx, Guid id, UserService users, CancellationToken ct) =>
        {
            await users.UpdateAsync(id, ctx.User.RequireId(), null, false, null, ct); // disable, never hard-delete
            return Results.NoContent();
        });
        a.MapPost("/users/{id:guid}/reset-password", async (HttpContext ctx, Guid id, UserService users, CancellationToken ct) =>
            Results.Json(new { temporaryPassword = await users.ResetPasswordAsync(id, ctx.User.RequireId(), ct) }));
        a.MapPost("/users/{id:guid}/unlock", async (HttpContext ctx, Guid id, UserService users, CancellationToken ct) => { await users.UnlockAsync(id, ctx.User.RequireId(), ct); return Results.NoContent(); });
        a.MapPost("/users/{id:guid}/reset-mfa", async (HttpContext ctx, Guid id, UserService users, CancellationToken ct) => { await users.ResetMfaAsync(id, ctx.User.RequireId(), ct); return Results.NoContent(); });

        // ---- settings / signing / audit / jobs / conflicts / quarantine ----
        a.MapGet("/settings", async (SettingsService s, Microsoft.Extensions.Options.IOptions<AptOptions> apt, Microsoft.Extensions.Options.IOptions<RetentionOptions> ret,
            Microsoft.Extensions.Options.IOptions<SecurityOptions> sec, Microsoft.Extensions.Options.IOptions<LimitsOptions> lim, CancellationToken ct) =>
            Results.Json(new
            {
                version = typeof(AdminApi).Assembly.GetName().Version?.ToString(3) ?? "1.0.0",
                archAllowList = await s.GetAsync<string[]>(SettingsService.ArchAllowList, ct) ?? Architectures.ParseList(apt.Value.Architectures),
                reservedNames = await s.GetAsync<string[]>(SettingsService.ReservedNames, ct) ?? [],
                retention = ret.Value, limits = lim.Value, security = new { sec.Value.PublicScheme, sec.Value.ClientIpHeader, sec.Value.TrustedProxies }
            }));
        a.MapPatch("/settings", async (HttpContext ctx, SettingsBody b, SettingsService s, IAuditService audit, CancellationToken ct) =>
        {
            if (b.ArchAllowList is not null)
            {
                var list = b.ArchAllowList.Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0).Distinct().ToArray();
                if (list.Length == 0 || list.Any(x => !System.Text.RegularExpressions.Regex.IsMatch(x, "^[a-z0-9][a-z0-9-]*$"))) throw new ServiceException("validation_error", "Invalid architecture allow-list.");
                await s.SetAsync(SettingsService.ArchAllowList, list, ctx.User.Id(), ct);
            }
            if (b.ReservedNames is not null)
                await s.SetAsync(SettingsService.ReservedNames, b.ReservedNames.Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0).Distinct().ToArray(), ctx.User.Id(), ct);
            await audit.WriteAsync("settings.updated", ctx.User.Id(), "settings", null, ct: ct);
            return Results.NoContent();
        });
        a.MapGet("/signing", async (ISigner signer, CancellationToken ct) =>
        {
            await signer.EnsureReadyAsync(ct);
            return Results.Json(new { fingerprint = signer.Fingerprint, expires = await signer.GetKeyExpiryAsync(ct) });
        });
        a.MapGet("/audit", async (IDbContextFactory<AppDbContext> dbf, string? action, Guid? actor, string? format, string? cursor, int? limit, CancellationToken ct) =>
        {
            var offset = int.TryParse(cursor, out var o) ? o : 0;
            var lim = Math.Clamp(limit ?? 50, 1, format == "csv" ? 10000 : 200);
            await using var db = await dbf.CreateDbContextAsync(ct);
            var q = db.AuditLog.AsNoTracking().AsQueryable();
            if (!string.IsNullOrEmpty(action)) q = q.Where(x => x.Action.StartsWith(action));
            if (actor is not null) q = q.Where(x => x.ActorUserId == actor);
            var rows = await q.OrderByDescending(x => x.Id).Skip(offset).Take(lim + 1).ToListAsync(ct);
            if (format == "csv")
            {
                var sb = new System.Text.StringBuilder("id,occurred_at,actor,ip,action,target_type,target_id,outcome,metadata\n");
                foreach (var r in rows.Take(lim))
                    sb.Append(r.Id).Append(',').Append(r.OccurredAt.ToString("O")).Append(',').Append(Csv(r.ActorUserId?.ToString() ?? r.ActorLabel)).Append(',')
                      .Append(Csv(r.ActorIp?.ToString())).Append(',').Append(Csv(r.Action)).Append(',').Append(Csv(r.TargetType)).Append(',').Append(Csv(r.TargetId)).Append(',')
                      .Append(r.Outcome).Append(',').Append(Csv(r.Metadata)).Append('\n');
                return Results.Text(sb.ToString(), "text/csv");
            }
            return Results.Json(CoreApi.Page(rows.Select(r => new { r.Id, r.OccurredAt, r.ActorUserId, r.ActorLabel, ip = r.ActorIp?.ToString(), r.Action, r.TargetType, r.TargetId, r.Outcome, metadata = JsonDocument.Parse(r.Metadata).RootElement }).ToList(), offset, lim));
        });
        a.MapPost("/apt/rebuild", async (JobQueue q, CancellationToken ct) =>
        {
            await q.EnqueueAsync(JobKind.RebuildApt, null, "rebuild", ct: ct);
            return Results.Accepted();
        });
        a.MapGet("/conflicts", async (IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var rows = await (from v in db.PackageVariants.AsNoTracking()
                              join p in db.Packages.AsNoTracking() on v.PackageId equals p.Id
                              where db.PackageSources.Count(s => s.VariantId == v.Id) > 1
                              select new
                              {
                                  variantId = v.Id, package = p.Name, v.Version, v.Architecture,
                                  sources = db.PackageSources.Where(s => s.VariantId == v.Id).Join(db.Repositories, s => s.RepositoryId, r => r.Id,
                                      (s, r) => new { repository = r.FullName, r.Id, r.SourcePriority, s.IsWinner, identical = s.BlobId == v.BlobId }).ToList()
                              }).Take(500).ToListAsync(ct);
            return Results.Json(new { items = rows.Where(r => r.sources.Any(s => !s.identical)) });
        });
        a.MapGet("/quarantine", async (IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var rows = await (from v in db.PackageVariants.AsNoTracking()
                              join p in db.Packages.AsNoTracking() on v.PackageId equals p.Id
                              where v.State == VariantState.Quarantined
                              select new { variantId = v.Id, package = p.Name, v.Version, v.Architecture, reason = v.QuarantineReason, v.FirstSeenAt }).ToListAsync(ct);
            return Results.Json(new { items = rows });
        });
        a.MapPost("/variants/{id:guid}/quarantine", (HttpContext ctx, Guid id, IDbContextFactory<AppDbContext> dbf, SyncService sync, IAuditService audit, CancellationToken ct) =>
            SetVariantState(ctx, id, VariantState.Quarantined, "admin", dbf, sync, audit, ct));
        a.MapPost("/variants/{id:guid}/release", (HttpContext ctx, Guid id, IDbContextFactory<AppDbContext> dbf, SyncService sync, IAuditService audit, CancellationToken ct) =>
            SetVariantState(ctx, id, VariantState.Active, null, dbf, sync, audit, ct));
        a.MapGet("/jobs", async (IDbContextFactory<AppDbContext> dbf, string? state, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var q = db.Jobs.AsNoTracking().AsQueryable();
            if (!string.IsNullOrEmpty(state)) q = q.Where(j => j.State == state);
            return Results.Json(new { items = await q.OrderByDescending(j => j.UpdatedAt).Take(200).Select(j => new { j.Id, j.Kind, j.State, j.Attempts, j.MaxAttempts, j.RunAfter, j.LastError, j.UpdatedAt }).ToListAsync(ct) });
        });
        a.MapPost("/jobs/{id:guid}/retry", async (Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var n = await db.Jobs.Where(j => j.Id == id && (j.State == JobState.Dead || j.State == JobState.Failed))
                .ExecuteUpdateAsync(s => s.SetProperty(j => j.State, JobState.Pending).SetProperty(j => j.Attempts, 0).SetProperty(j => j.RunAfter, DateTimeOffset.UtcNow), ct);
            return n == 0 ? throw new ServiceException("invalid_state", "Job is not failed.", 409) : Results.Accepted();
        });
    }

    private static async Task<IResult> SetVariantState(HttpContext ctx, Guid id, string state, string? reason, IDbContextFactory<AppDbContext> dbf, SyncService sync, IAuditService audit, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var v = await db.PackageVariants.FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new ServiceException("not_found", "Variant not found.", 404);
        v.State = state; v.QuarantineReason = reason;
        if (state == VariantState.Quarantined) v.PublishedAt = null;
        await db.SaveChangesAsync(ct);
        await sync.RequestPublishAsync(ct);
        await audit.WriteAsync($"variant.{(state == VariantState.Quarantined ? "quarantined" : "released")}", ctx.User.Id(), "variant", id.ToString(), ct: ct);
        return Results.NoContent();
    }

    private static string Csv(string? s)
    {
        if (s is null) return "";
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s; // CSV injection guard
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }
}
