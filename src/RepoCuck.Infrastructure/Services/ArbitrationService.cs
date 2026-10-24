using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

/// <summary>Winner selection, promotion on ineligibility and admin re-arbitration (spec §6.4).</summary>
public sealed class ArbitrationService(IBlobStore blobs, IClock clock, IOptions<RetentionOptions> ret, IAuditService audit, ILogger<ArbitrationService> log)
{
    public static bool IsPublishable(Repository r, DateTimeOffset now, TimeSpan grace) =>
        r.State is RepoState.Active or RepoState.Paused
        || (r.State == RepoState.Removed && r.RemovedAt is { } at && at > now - grace);

    private sealed record Candidate(PackageSource Source, Repository Repo, long GithubAssetId);

    private static bool Eligible(Repository r, string arch, DateTimeOffset now, TimeSpan grace) =>
        IsPublishable(r, now, grace) && (arch == "all" || r.Architectures.Contains(arch));

    /// <summary>Promotes the best publishable alternate wherever the current winner's repository is ineligible. Returns changes made.</summary>
    public async Task<int> PromoteIneligibleAsync(AppDbContext db, CancellationToken ct)
    {
        var now = clock.UtcNow;
        var grace = TimeSpan.FromDays(ret.Value.OrphanGraceDays);
        var broken = await (from s in db.PackageSources
                            join r in db.Repositories on s.RepositoryId equals r.Id
                            join v in db.PackageVariants on s.VariantId equals v.Id
                            where s.IsWinner && v.State != VariantState.Tombstoned
                                  && (r.State == RepoState.Blocked || r.State == RepoState.Rejected
                                      || (r.State == RepoState.Removed && (r.RemovedAt == null || r.RemovedAt <= now - grace)))
                            select v).ToListAsync(ct);
        var changes = 0;
        foreach (var v in broken)
        {
            var best = await BestAlternateAsync(db, v, now, grace, ct);
            if (best is not null)
            {
                await SwapAsync(db, v, best, "promotion", ct);
                changes++;
            }
            else
            {
                v.State = VariantState.Tombstoned; v.TombstonedAt = now; v.QuarantineReason = TombReason.RepoIneligible;
                await audit.WriteAsync("variant.tombstoned", null, "variant", v.Id.ToString(), metadata: new { reason = "winner_ineligible" }, ct: ct);
                changes++;
            }
        }
        if (changes > 0) await db.SaveChangesAsync(ct);
        return changes;
    }

    /// <summary>Admin re-arbitration: for every variant with a source from <paramref name="repoId"/> (or all if null), pick the best-ranked eligible source.</summary>
    public async Task<int> RearbitrateAsync(AppDbContext db, Guid? repoId, Guid? actor, CancellationToken ct)
    {
        var now = clock.UtcNow;
        var grace = TimeSpan.FromDays(ret.Value.OrphanGraceDays);
        var q = db.PackageVariants.Where(v => v.State != VariantState.Tombstoned);
        if (repoId is not null)
            q = q.Where(v => db.PackageSources.Any(s => s.VariantId == v.Id && s.RepositoryId == repoId));
        var variants = await q.Where(v => db.PackageSources.Count(s => s.VariantId == v.Id) > 1).ToListAsync(ct);
        var changes = 0;
        foreach (var v in variants)
        {
            var cands = await Candidates(db, v, now, grace, includeWinner: true, ct);
            var best = cands.OrderByDescending(c => c.Repo.SourcePriority).ThenBy(c => c.Repo.CreatedAt)
                .ThenBy(c => c.Repo.GithubRepoId).ThenBy(c => c.GithubAssetId).FirstOrDefault();
            if (best is null || best.Source.IsWinner) continue;
            await SwapAsync(db, v, best.Source, "rearbitration", ct);
            changes++;
        }
        if (changes > 0)
        {
            await db.SaveChangesAsync(ct);
            await audit.WriteAsync("variants.rearbitrated", actor, "repository", repoId?.ToString(), metadata: new { changes }, ct: ct);
        }
        return changes;
    }

    /// <summary>Brings a repo-ineligible tombstone back to life from <paramref name="source"/> (its repository is publishable again).</summary>
    public async Task ReviveAsync(AppDbContext db, PackageVariant v, PackageSource source, CancellationToken ct)
    {
        await SwapAsync(db, v, source, "revival", ct);
        v.State = VariantState.Active; v.QuarantineReason = null; v.TombstonedAt = null; v.PublishedAt = null;
    }

    private async Task<List<Candidate>> Candidates(AppDbContext db, PackageVariant v, DateTimeOffset now, TimeSpan grace, bool includeWinner, CancellationToken ct)
    {
        var rows = await (from s in db.PackageSources
                          join r in db.Repositories on s.RepositoryId equals r.Id
                          join a in db.ReleaseAssets on s.AssetId equals a.Id
                          where s.VariantId == v.Id && (includeWinner || !s.IsWinner)
                          select new Candidate(s, r, a.GithubAssetId)).ToListAsync(ct);
        return rows.Where(c => Eligible(c.Repo, v.Architecture, now, grace)).ToList();
    }

    private async Task<PackageSource?> BestAlternateAsync(AppDbContext db, PackageVariant v, DateTimeOffset now, TimeSpan grace, CancellationToken ct)
    {
        var cands = await Candidates(db, v, now, grace, includeWinner: false, ct);
        return cands.OrderByDescending(c => c.Repo.SourcePriority).ThenBy(c => c.Repo.CreatedAt)
            .ThenBy(c => c.Repo.GithubRepoId).ThenBy(c => c.GithubAssetId).FirstOrDefault()?.Source;
    }

    /// <summary>Swaps published bytes of a variant to the given source (new pool filename if bytes differ).</summary>
    private async Task SwapAsync(AppDbContext db, PackageVariant v, PackageSource to, string reason, CancellationToken ct)
    {
        var blob = await db.Blobs.FirstAsync(b => b.Id == to.BlobId, ct);
        var oldWinner = await db.PackageSources.Where(s => s.VariantId == v.Id && s.IsWinner).ToListAsync(ct);
        foreach (var o in oldWinner) o.IsWinner = false;
        await db.SaveChangesAsync(ct); // clear winner flag first (partial unique index)
        to.IsWinner = true;
        if (v.Sha256 != blob.Sha256)
        {
            ControlFile? control = null;
            try
            {
                await using var s = blobs.OpenRead(blob.StorageKey);
                control = DebInspector.Inspect(s, blob.SizeBytes + 1024 * 1024).Control;
            }
            catch (Exception e) { log.LogWarning(e, "Could not re-read control of promoted blob {Sha}", blob.Sha256); }
            var cf = control ?? new ControlFile();
            if (control is null)
            {
                var pkgName = (await db.Packages.FirstAsync(p => p.Id == v.PackageId, ct)).Name;
                cf.Fields.Add(new("Package", pkgName)); cf.Fields.Add(new("Version", v.Version)); cf.Fields.Add(new("Architecture", v.Architecture));
            }
            else { v.Control = ControlJson.Serialize(control.Fields); v.Description = control.Description; }
            v.Filename = await SyncService.AllocateFilenameAsync(db, cf, blob, ct);
            v.BlobId = blob.Id; v.Sha256 = blob.Sha256; v.Sha512 = blob.Sha512; v.SizeBytes = blob.SizeBytes;
            v.PublishedAt = null;
        }
        await audit.WriteAsync("variant.winner_changed", null, "variant", v.Id.ToString(), metadata: new { reason, source = to.Id }, ct: ct);
    }
}
