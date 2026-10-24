using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

public sealed class RetentionService(IDbContextFactory<AppDbContext> dbf, IBlobStore blobs, IClock clock, IAuditService audit,
    IOptions<RetentionOptions> ret, IOptions<RequestsOptions> reqOpt, SyncService sync, ILogger<RetentionService> log)
{
    public async Task SweepAsync(CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = clock.UtcNow;
        var changed = false;

        // 1. Keep newest N versions per (package, arch, channel).
        var groups = await db.PackageVariants.Where(v => v.State == VariantState.Active)
            .Select(v => new { v.Id, v.PackageId, v.Architecture, v.Channel, v.Version }).ToListAsync(ct);
        var tomb = new List<Guid>();
        foreach (var g in groups.GroupBy(v => (v.PackageId, v.Architecture, v.Channel)))
        {
            var ordered = g.OrderByDescending(v => DebianVersion.TryParse(v.Version, out var d) ? d : DebianVersion.Parse("0")).ToList();
            tomb.AddRange(ordered.Skip(ret.Value.VersionsPerPackage).Select(v => v.Id));
        }
        if (tomb.Count > 0)
        {
            await db.PackageVariants.Where(v => tomb.Contains(v.Id)).ExecuteUpdateAsync(s => s.SetProperty(v => v.State, VariantState.Tombstoned), ct);
            await audit.WriteAsync("retention.tombstoned", null, "variant", null, metadata: new { count = tomb.Count }, ct: ct);
            changed = true;
        }

        // 2. Removed repositories past grace: tombstone variants that have no other publishable source (promotion handles alternates).
        // (PublisherService.PromoteIneligibleAsync performs this on the next publish; trigger one.)
        var grace = TimeSpan.FromDays(ret.Value.OrphanGraceDays);
        var expired = await db.Repositories.AnyAsync(r => r.State == RepoState.Removed && r.RemovedAt != null && r.RemovedAt <= now - grace, ct);
        if (expired) changed = true;

        // 3. Hard-delete removed repositories 90 days after grace when nothing is published from them.
        var cutoff = now - grace - TimeSpan.FromDays(90);
        var old = await db.Repositories.Where(r => r.State == RepoState.Removed && r.RemovedAt != null && r.RemovedAt <= cutoff).ToListAsync(ct);
        foreach (var r in old)
        {
            var hasWinners = await db.PackageSources.AnyAsync(s => s.RepositoryId == r.Id && s.IsWinner, ct);
            if (hasWinners) continue;
            await db.ChangeRequests.Where(c => c.RepositoryId == r.Id).ExecuteDeleteAsync(ct);
            db.Repositories.Remove(r);
        }
        await db.SaveChangesAsync(ct);

        // 7. Expire stale proposed repositories.
        var proposedCutoff = now.AddDays(-reqOpt.Value.ProposedExpiryDays);
        var stale = await db.Repositories.Where(r => r.State == RepoState.Proposed && r.CreatedAt < proposedCutoff).ToListAsync(ct);
        foreach (var r in stale)
        {
            r.State = RepoState.Rejected; r.StateReason = "expired"; r.UpdatedAt = now;
            await db.ChangeRequests.Where(c => c.RepositoryId == r.Id && c.Status == RequestStatus.Pending)
                .ExecuteUpdateAsync(s => s.SetProperty(c => c.Status, RequestStatus.Rejected).SetProperty(c => c.DecidedAt, now).SetProperty(c => c.DecisionNote, "expired"), ct);
        }
        await db.SaveChangesAsync(ct);

        // 5. Generations beyond both count and age, per suite.
        foreach (var suite in await db.AptSuites.ToListAsync(ct))
        {
            var current = await db.AptCurrent.Where(c => c.SuiteId == suite.Id).Select(c => c.GenerationId).FirstOrDefaultAsync(ct);
            var gens = await db.AptGenerations.Where(g => g.SuiteId == suite.Id).OrderByDescending(g => g.GenerationNo).ToListAsync(ct);
            var minAge = TimeSpan.FromHours(Math.Max(suite.RetainHours, ret.Value.GenerationHours));
            var count = Math.Max(suite.RetainGenerations, ret.Value.GenerationCount);
            var drop = gens.Skip(count).Where(g => g.Id != current && (g.ActivatedAt ?? g.CreatedAt) < now - minAge).ToList();
            foreach (var g in drop) db.AptGenerations.Remove(g);
        }
        await db.SaveChangesAsync(ct);

        // 4. Blob GC: unreferenced and older than grace.
        var blobCutoff = now.AddHours(-ret.Value.BlobGraceHours);
        var candidates = await db.Blobs.Where(b => b.LastReferencedAt < blobCutoff
                && !db.PackageVariants.Any(v => v.BlobId == b.Id)
                && !db.PackageSources.Any(s => s.BlobId == b.Id)
                && !db.AptGenerationFiles.Any(f => f.BlobId == b.Id)
                && !db.AptGenerations.Any(g => g.ReleaseBlobId == b.Id || g.InreleaseBlobId == b.Id || g.ReleaseGpgBlobId == b.Id))
            .ToListAsync(ct);
        foreach (var b in candidates)
        {
            await blobs.DeleteAsync(b.StorageKey, ct);
            db.Blobs.Remove(b);
        }
        await db.SaveChangesAsync(ct);
        if (candidates.Count > 0) log.LogInformation("Retention removed {Count} unreferenced blobs", candidates.Count);
        if (changed) await sync.RequestPublishAsync(ct);
    }
}
