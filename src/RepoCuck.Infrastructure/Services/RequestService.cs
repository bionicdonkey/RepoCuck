using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

public sealed record CreateRequestInput(string Kind, string? Owner, string? Name, string? Url, Guid? RepositoryId, string[]? Architectures, string? Note);
public sealed record CreateRequestResult(ChangeRequest Request, Repository Repository);
public sealed record ApproveOverrides(string[]? Architectures, bool? IncludePrereleases, int? HoldbackHours, string? Note);

public sealed class RequestService(
    IDbContextFactory<AppDbContext> dbf, IGitHubClient gh, IClock clock, JobQueue jobs, IAuditService audit,
    SettingsService settings, IOptions<AptOptions> apt, IOptions<LimitsOptions> limits)
{
    private async Task<string[]> AllowAsync(CancellationToken ct) =>
        await settings.GetAsync<string[]>(SettingsService.ArchAllowList, ct) ?? Architectures.ParseList(apt.Value.Architectures);

    public async Task<CreateRequestResult> CreateAsync(Guid userId, CreateRequestInput input, CancellationToken ct)
    {
        var allow = await AllowAsync(ct);
        var archs = Architectures.Normalize(input.Architectures, allow);
        if (input.Kind is not (RequestKind.AddRepo or RequestKind.AddArch)) throw new ServiceException("validation_error", "kind must be add_repo or add_arch.");
        if (archs.Length == 0) throw new ServiceException("validation_error", $"architectures must contain at least one of: {string.Join(", ", allow)}.");
        if (input.Note is { Length: > 1000 }) throw new ServiceException("validation_error", "note is too long.");

        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = clock.UtcNow;
        var pending = await db.ChangeRequests.CountAsync(r => r.RequestedBy == userId && r.Status == RequestStatus.Pending, ct);
        if (pending >= limits.Value.PendingRequestsPerUser) throw new ServiceException("request_limit", "Too many pending requests.", 422);
        var recent = await db.ChangeRequests.CountAsync(r => r.RequestedBy == userId && r.CreatedAt > now.AddHours(-1), ct);
        if (recent >= limits.Value.RequestsPerHour) throw new ServiceException("rate_limited", "Too many requests; try again later.", 429);

        return input.Kind == RequestKind.AddRepo
            ? await CreateAddRepoAsync(db, userId, input, archs, ct)
            : await CreateAddArchAsync(db, userId, input, archs, ct);
    }

    private async Task<CreateRequestResult> CreateAddRepoAsync(AppDbContext db, Guid userId, CreateRequestInput input, string[] archs, CancellationToken ct)
    {
        string owner, name;
        if (!string.IsNullOrWhiteSpace(input.Url)) { if (!RepoRef.TryParse(input.Url, out owner, out name)) throw new ServiceException("validation_error", "Not a valid GitHub repository reference."); }
        else if (!RepoRef.TryParse($"{input.Owner}/{input.Name}", out owner, out name)) throw new ServiceException("validation_error", "owner and name (or url) are required.");

        GhRepo meta;
        try { meta = await gh.GetRepoAsync(owner, name, ct); }
        catch (GitHubException e) when (e.Code == "not_found") { throw new ServiceException("repository_not_found", "Repository not found or not public.", 404); }
        catch (GitHubException) { throw new ServiceException("upstream_unavailable", "GitHub is unavailable; try again later.", 503); }

        var now = clock.UtcNow;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var repo = await db.Repositories.FirstOrDefaultAsync(r => r.GithubRepoId == meta.Id, ct);
            if (repo is not null)
            {
                if (repo.State == RepoState.Blocked) throw new ServiceException("repository_blocked", "This repository cannot be requested.", 403);
                var dup = await db.ChangeRequests.AnyAsync(r => r.RepositoryId == repo.Id && r.RequestedBy == userId && r.Kind == RequestKind.AddRepo && r.Status == RequestStatus.Pending, ct);
                if (dup) throw new ServiceException("request_pending", "You already have a pending request for this repository.", 409, new { repositoryId = repo.Id });
                if (repo.State != RepoState.Rejected)
                    throw new ServiceException("already_watched", $"{repo.FullName} is already in the watch list.", 409, new { repositoryId = repo.Id, state = repo.State });
                repo.State = RepoState.Proposed; repo.StateReason = null; repo.Architectures = archs; repo.UpdatedAt = now; repo.ProposedBy = userId;
            }
            else
            {
                repo = new Repository
                {
                    Id = Ids.New(), GithubRepoId = meta.Id, Owner = meta.Owner, Name = meta.Name, FullName = meta.FullName, HtmlUrl = meta.HtmlUrl,
                    Description = meta.Description, LicenseSpdx = meta.License, DefaultBranch = meta.DefaultBranch, IsArchived = meta.Archived,
                    State = RepoState.Proposed, Architectures = archs, ProposedBy = userId, CreatedAt = now, UpdatedAt = now
                };
                db.Repositories.Add(repo);
            }
            var req = new ChangeRequest { Id = Ids.New(), Kind = RequestKind.AddRepo, RepositoryId = repo.Id, RequestedBy = userId, Architectures = archs, Note = input.Note, CreatedAt = now };
            db.ChangeRequests.Add(req);
            try { await db.SaveChangesAsync(ct); }
            catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: "23505" })
            {
                db.ChangeTracker.Clear(); // lost a race on github_repo_id; re-evaluate against the winner
                continue;
            }
            await jobs.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = repo.Id, trigger = "quarantine", reevaluate = false }, $"sync:{repo.Id}", ct: ct);
            await audit.WriteAsync("request.created", userId, "request", req.Id.ToString(), metadata: new { kind = req.Kind, repo = repo.FullName }, ct: ct);
            return new CreateRequestResult(req, repo);
        }
        throw new ServiceException("already_watched", "Repository is already in the watch list.", 409);
    }

    private async Task<CreateRequestResult> CreateAddArchAsync(AppDbContext db, Guid userId, CreateRequestInput input, string[] archs, CancellationToken ct)
    {
        if (input.RepositoryId is null) throw new ServiceException("validation_error", "repositoryId is required for add_arch.");
        var repo = await db.Repositories.FirstOrDefaultAsync(r => r.Id == input.RepositoryId, ct) ?? throw new ServiceException("not_found", "Repository not found.", 404);
        if (repo.State is not (RepoState.Active or RepoState.Paused))
            throw new ServiceException("invalid_state", "Architectures can only be requested for active or paused repositories.", 409);
        var add = archs.Except(repo.Architectures).ToArray();
        if (add.Length == 0) throw new ServiceException("already_enabled", "Those architectures are already enabled.", 409, new { repositoryId = repo.Id });
        var dup = await db.ChangeRequests.AnyAsync(r => r.RepositoryId == repo.Id && r.RequestedBy == userId && r.Kind == RequestKind.AddArch && r.Status == RequestStatus.Pending, ct);
        if (dup) throw new ServiceException("request_pending", "You already have a pending architecture request for this repository.", 409, new { repositoryId = repo.Id });
        var req = new ChangeRequest { Id = Ids.New(), Kind = RequestKind.AddArch, RepositoryId = repo.Id, RequestedBy = userId, Architectures = add, Note = input.Note, CreatedAt = clock.UtcNow };
        db.ChangeRequests.Add(req);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("request.created", userId, "request", req.Id.ToString(), metadata: new { kind = req.Kind, repo = repo.FullName, archs = add }, ct: ct);
        return new CreateRequestResult(req, repo);
    }

    public async Task<ChangeRequest> ApproveAsync(Guid requestId, Guid adminId, ApproveOverrides? o, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var req = await db.ChangeRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct) ?? throw new ServiceException("not_found", "Request not found.", 404);
        if (req.Status != RequestStatus.Pending) throw new ServiceException("invalid_state", "Request is not pending.", 409);
        var repo = await db.Repositories.FirstAsync(r => r.Id == req.RepositoryId, ct);
        var allow = await AllowAsync(ct);
        var now = clock.UtcNow;
        var overrideArchs = o?.Architectures is null ? null : Architectures.Normalize(o.Architectures, allow);
        if (overrideArchs is { Length: 0 }) throw new ServiceException("validation_error", "architectures must not be empty.");

        if (req.Kind == RequestKind.AddRepo)
        {
            if (repo.State != RepoState.Proposed) throw new ServiceException("invalid_state", $"Repository is {repo.State}, not proposed.", 409);
            var siblings = await db.ChangeRequests.Where(r => r.RepositoryId == repo.Id && r.Kind == RequestKind.AddRepo && r.Status == RequestStatus.Pending).ToListAsync(ct);
            repo.Architectures = overrideArchs ?? Architectures.Normalize(siblings.SelectMany(s => s.Architectures), allow);
            repo.State = RepoState.Active; repo.StateReason = null; repo.ApprovedBy = adminId; repo.ApprovedAt = now; repo.NextSyncAt = now;
            foreach (var s in siblings) { s.Status = RequestStatus.Approved; s.DecidedBy = adminId; s.DecidedAt = now; s.DecisionNote = s.Id == req.Id ? o?.Note : "approved with a sibling request"; }
        }
        else
        {
            if (repo.State is not (RepoState.Active or RepoState.Paused)) throw new ServiceException("invalid_state", $"Repository is {repo.State}.", 409);
            repo.Architectures = Architectures.Normalize(repo.Architectures.Concat(overrideArchs ?? req.Architectures), allow);
            req.Status = RequestStatus.Approved; req.DecidedBy = adminId; req.DecidedAt = now; req.DecisionNote = o?.Note;
        }
        if (o?.IncludePrereleases is { } ip) repo.IncludePrereleases = ip;
        if (o?.HoldbackHours is { } hb) repo.HoldbackHours = Math.Clamp(hb, 0, 720);
        repo.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        await jobs.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = repo.Id, trigger = "manual", reevaluate = true }, $"sync:{repo.Id}", ct: ct);
        await audit.WriteAsync("request.approved", adminId, "request", req.Id.ToString(), metadata: new { repo = repo.FullName, kind = req.Kind, archs = repo.Architectures, requester = req.RequestedBy }, ct: ct);
        return req;
    }

    public async Task<ChangeRequest> RejectAsync(Guid requestId, Guid adminId, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 500) throw new ServiceException("validation_error", "reason is required (1-500 characters).");
        await using var db = await dbf.CreateDbContextAsync(ct);
        var req = await db.ChangeRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct) ?? throw new ServiceException("not_found", "Request not found.", 404);
        if (req.Status != RequestStatus.Pending) throw new ServiceException("invalid_state", "Request is not pending.", 409);
        var repo = await db.Repositories.FirstAsync(r => r.Id == req.RepositoryId, ct);
        var now = clock.UtcNow;
        if (req.Kind == RequestKind.AddRepo && repo.State == RepoState.Proposed)
        {
            var siblings = await db.ChangeRequests.Where(r => r.RepositoryId == repo.Id && r.Kind == RequestKind.AddRepo && r.Status == RequestStatus.Pending).ToListAsync(ct);
            foreach (var s in siblings) { s.Status = RequestStatus.Rejected; s.DecidedBy = adminId; s.DecidedAt = now; s.DecisionNote = reason; }
            repo.State = RepoState.Rejected; repo.StateReason = reason; repo.UpdatedAt = now;
        }
        else { req.Status = RequestStatus.Rejected; req.DecidedBy = adminId; req.DecidedAt = now; req.DecisionNote = reason; }
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("request.rejected", adminId, "request", req.Id.ToString(), metadata: new { repo = repo.FullName, reason }, ct: ct);
        return req;
    }

    public async Task CancelAsync(Guid requestId, Guid userId, bool isAdmin, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var req = await db.ChangeRequests.FirstOrDefaultAsync(r => r.Id == requestId, ct) ?? throw new ServiceException("not_found", "Request not found.", 404);
        if (req.RequestedBy != userId && !isAdmin) throw new ServiceException("forbidden", "Only the requester can cancel a request.", 403);
        if (req.Status != RequestStatus.Pending) throw new ServiceException("invalid_state", "Request is not pending.", 409);
        req.Status = RequestStatus.Cancelled; req.DecidedBy = userId; req.DecidedAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("request.cancelled", userId, "request", req.Id.ToString(), ct: ct);
    }
}

public sealed record RepoPatch(string[]? Architectures, bool? IncludePrereleases, int? HoldbackHours, string? AssetIncludeGlob,
    string? AssetExcludeGlob, long? MaxAssetBytes, int? SyncIntervalMinutes, string? Notes, int? SourcePriority);

public sealed class RepositoryAdminService(
    IDbContextFactory<AppDbContext> dbf, IGitHubClient gh, IClock clock, JobQueue jobs, IAuditService audit, SyncService sync,
    ArbitrationService arbitration, SettingsService settings, IOptions<AptOptions> apt)
{
    private async Task<string[]> AllowAsync(CancellationToken ct) =>
        await settings.GetAsync<string[]>(SettingsService.ArchAllowList, ct) ?? Architectures.ParseList(apt.Value.Architectures);

    public async Task<Repository> AddDirectAsync(Guid adminId, string? owner, string? name, string? url, string[]? archs, CancellationToken ct)
    {
        string o, n;
        if (!string.IsNullOrWhiteSpace(url)) { if (!RepoRef.TryParse(url, out o, out n)) throw new ServiceException("validation_error", "Invalid repository reference."); }
        else if (!RepoRef.TryParse($"{owner}/{name}", out o, out n)) throw new ServiceException("validation_error", "owner and name (or url) are required.");
        var a = Architectures.Normalize(archs, await AllowAsync(ct));
        if (a.Length == 0) throw new ServiceException("validation_error", "At least one allowed architecture is required.");
        GhRepo meta;
        try { meta = await gh.GetRepoAsync(o, n, ct); }
        catch (GitHubException e) when (e.Code == "not_found") { throw new ServiceException("repository_not_found", "Repository not found or not public.", 404); }
        catch (GitHubException) { throw new ServiceException("upstream_unavailable", "GitHub is unavailable.", 503); }

        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = clock.UtcNow;
        var repo = await db.Repositories.FirstOrDefaultAsync(r => r.GithubRepoId == meta.Id, ct);
        if (repo is null)
        {
            repo = new Repository { Id = Ids.New(), GithubRepoId = meta.Id, CreatedAt = now };
            db.Repositories.Add(repo);
        }
        else if (repo.State == RepoState.Blocked) throw new ServiceException("repository_blocked", "Repository is blocked; unblock it first.", 403);
        else if (repo.State is RepoState.Active or RepoState.Paused) throw new ServiceException("already_watched", $"{repo.FullName} is already in the watch list.", 409, new { repositoryId = repo.Id, state = repo.State });
        repo.Owner = meta.Owner; repo.Name = meta.Name; repo.FullName = meta.FullName; repo.HtmlUrl = meta.HtmlUrl; repo.Description = meta.Description;
        repo.LicenseSpdx = meta.License; repo.DefaultBranch = meta.DefaultBranch; repo.IsArchived = meta.Archived;
        repo.Architectures = a; repo.State = RepoState.Active; repo.StateReason = null; repo.RemovedAt = null;
        repo.ApprovedBy = adminId; repo.ApprovedAt = now; repo.ProposedBy ??= adminId; repo.NextSyncAt = now; repo.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        // pending requests for this repository are satisfied
        await db.ChangeRequests.Where(r => r.RepositoryId == repo.Id && r.Kind == RequestKind.AddRepo && r.Status == RequestStatus.Pending)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, RequestStatus.Approved).SetProperty(r => r.DecidedBy, adminId)
                .SetProperty(r => r.DecidedAt, now).SetProperty(r => r.DecisionNote, "added directly by an admin"), ct);
        await jobs.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = repo.Id, trigger = "manual", reevaluate = true }, $"sync:{repo.Id}", ct: ct);
        await audit.WriteAsync("repository.added", adminId, "repository", repo.Id.ToString(), metadata: new { repo = repo.FullName, archs = a }, ct: ct);
        return repo;
    }

    private static async Task<Repository> Load(AppDbContext db, Guid id, CancellationToken ct) =>
        await db.Repositories.FirstOrDefaultAsync(r => r.Id == id, ct) ?? throw new ServiceException("not_found", "Repository not found.", 404);

    public async Task<Repository> PatchAsync(Guid id, Guid adminId, RepoPatch p, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var repo = await Load(db, id, ct);
        var before = repo.Architectures;
        var publishNeeded = false;
        if (p.Architectures is not null)
        {
            var a = Architectures.Normalize(p.Architectures, await AllowAsync(ct));
            if (a.Length == 0) throw new ServiceException("validation_error", "architectures must not be empty.");
            repo.Architectures = a;
            publishNeeded |= !a.SequenceEqual(before);
        }
        if (p.IncludePrereleases is { } ip) { publishNeeded |= ip != repo.IncludePrereleases; repo.IncludePrereleases = ip; }
        if (p.HoldbackHours is { } hb) repo.HoldbackHours = Math.Clamp(hb, 0, 720);
        if (p.AssetIncludeGlob is { Length: > 0 } inc) repo.AssetIncludeGlob = inc;
        if (p.AssetExcludeGlob is not null) repo.AssetExcludeGlob = p.AssetExcludeGlob.Length == 0 ? null : p.AssetExcludeGlob;
        if (p.MaxAssetBytes is { } mb) repo.MaxAssetBytes = mb <= 0 ? null : mb;
        if (p.SyncIntervalMinutes is { } si) repo.SyncIntervalMinutes = Math.Clamp(si, 5, 1440);
        if (p.Notes is not null) repo.Notes = p.Notes.Length > 2000 ? p.Notes[..2000] : p.Notes;
        if (p.SourcePriority is { } sp) repo.SourcePriority = sp;
        repo.UpdatedAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);
        if (repo.Architectures.Except(before).Any() || p.IncludePrereleases == true)
            await jobs.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = repo.Id, trigger = "manual", reevaluate = true }, $"sync:{repo.Id}", ct: ct);
        if (publishNeeded) await sync.RequestPublishAsync(ct);
        await audit.WriteAsync("repository.updated", adminId, "repository", repo.Id.ToString(), metadata: p, ct: ct);
        return repo;
    }

    public async Task<Repository> SetStateAsync(Guid id, Guid adminId, string action, string? reason, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var repo = await Load(db, id, ct);
        var now = clock.UtcNow;
        switch (action)
        {
            case "pause":
                Require(repo, RepoState.Active); repo.State = RepoState.Paused; repo.NextSyncAt = null; break;
            case "resume":
                Require(repo, RepoState.Paused); repo.State = RepoState.Active; repo.NextSyncAt = now; break;
            case "remove":
                if (repo.State is RepoState.Removed or RepoState.Blocked) throw new ServiceException("invalid_state", $"Repository is {repo.State}.", 409);
                repo.State = RepoState.Removed; repo.RemovedAt = now; repo.NextSyncAt = null; repo.StateReason = reason; break;
            case "block":
                if (repo.State == RepoState.Blocked) throw new ServiceException("invalid_state", "Already blocked.", 409);
                repo.State = RepoState.Blocked; repo.StateReason = reason; repo.NextSyncAt = null;
                await db.ChangeRequests.Where(r => r.RepositoryId == repo.Id && r.Status == RequestStatus.Pending)
                    .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, RequestStatus.Rejected).SetProperty(r => r.DecidedBy, adminId)
                        .SetProperty(r => r.DecidedAt, now).SetProperty(r => r.DecisionNote, "repository blocked"), ct);
                break;
            case "unblock":
                Require(repo, RepoState.Blocked); repo.State = RepoState.Proposed; repo.StateReason = null; break;
            case "reinstate":
                Require(repo, RepoState.Removed); repo.State = RepoState.Active; repo.RemovedAt = null; repo.NextSyncAt = now; repo.StateReason = null; break;
            default: throw new ServiceException("validation_error", "Unknown action.");
        }
        repo.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        await sync.RequestPublishAsync(ct);
        await audit.WriteAsync("repository." + action, adminId, "repository", repo.Id.ToString(), metadata: new { repo = repo.FullName, reason }, ct: ct);
        return repo;
    }

    private static void Require(Repository r, string state)
    {
        if (r.State != state) throw new ServiceException("invalid_state", $"Repository is {r.State}, expected {state}.", 409);
    }

    public async Task EnqueueSyncAsync(Guid id, Guid adminId, bool reevaluate, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var repo = await Load(db, id, ct);
        if (repo.State is RepoState.Blocked or RepoState.Rejected or RepoState.Removed) throw new ServiceException("invalid_state", $"Repository is {repo.State}.", 409);
        await jobs.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = id, trigger = "manual", reevaluate }, $"sync:{id}", ct: ct);
        await audit.WriteAsync("repository.sync_requested", adminId, "repository", id.ToString(), ct: ct);
    }

    public async Task<int> RearbitrateAsync(Guid id, Guid adminId, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        await Load(db, id, ct);
        var n = await arbitration.RearbitrateAsync(db, id, adminId, ct);
        if (n > 0) await sync.RequestPublishAsync(ct);
        return n;
    }
}
