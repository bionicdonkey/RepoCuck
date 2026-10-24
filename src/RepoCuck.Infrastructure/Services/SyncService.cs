using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

public sealed class SyncService(
    IDbContextFactory<AppDbContext> dbf, IGitHubClient gh, IBlobStore blobs, IClock clock, JobQueue jobs, ArbitrationService arbitration,
    IOptions<AptOptions> apt, IOptions<GitHubOptions> ghOpt, IOptions<PolicyOptions> policyOpt, SettingsService settings,
    IAuditService audit, ILogger<SyncService> log)
{
    private static readonly string[] PermanentFailures = ["invalid_control", "digest_mismatch", "not_ar", "too_large", "unsupported_format", "no_debian_binary", "no_control", "bad_control_tar", "decompression_limit"];

    public async Task<SyncRun> SyncAsync(Guid repoId, string trigger, bool reevaluate, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var repo = await db.Repositories.FirstOrDefaultAsync(r => r.Id == repoId, ct);
        var run = new SyncRun { Id = Ids.New(), RepositoryId = repoId, Trigger = trigger, StartedAt = clock.UtcNow };
        if (repo is null) { run.Status = "failed"; run.Error = "repository not found"; return run; }
        if (repo.State is not (RepoState.Active or RepoState.Proposed) && trigger != "manual")
        {
            run.Status = "succeeded"; run.FinishedAt = clock.UtcNow; return run; // paused/removed/blocked: nothing to do
        }
        if (repo.State is RepoState.Blocked or RepoState.Rejected or RepoState.Removed)
        {
            run.Status = "succeeded"; run.FinishedAt = clock.UtcNow; return run;
        }
        db.SyncRuns.Add(run);
        await db.SaveChangesAsync(ct);

        var allow = await AllowListAsync(ct);
        var extra = await settings.GetAsync<string[]>(SettingsService.ReservedNames, ct);
        var policy = new PackagePolicy(policyOpt.Value, extra is null ? null : new HashSet<string>(extra, StringComparer.OrdinalIgnoreCase));
        var changed = false;
        try
        {
            var meta = await gh.GetRepoByIdAsync(repo.GithubRepoId, ct);
            ApplyMetadata(repo, meta);
            var first = repo.LastSyncedAt is null;
            var take = repo.State == RepoState.Proposed ? apt.Value.ProposedBackfillReleases
                : first ? apt.Value.InitialBackfillReleases : Math.Max(30, apt.Value.InitialBackfillReleases);
            var releases = await gh.GetReleasesAsync(repo.Owner, repo.Name, take, ct);
            run.ReleasesSeen = releases.Count;
            foreach (var rel in releases)
            {
                ct.ThrowIfCancellationRequested();
                changed |= await ProcessReleaseAsync(db, repo, rel, run, reevaluate, policy, allow, ct);
            }
            run.Status = run.AssetsFailed > 0 ? "partial" : "succeeded";
            repo.ConsecutiveFailures = 0;
            repo.LastSyncStatus = run.Status;
        }
        catch (GitHubRateLimitedException)
        {
            await FinishAsync(db, repo, run, "failed", "rate_limited", "GitHub rate limit", ct);
            throw;
        }
        catch (GitHubException e) when (e.Code == "not_found")
        {
            repo.ConsecutiveFailures++;
            await FinishAsync(db, repo, run, "failed", "upstream_unavailable", e.Message, ct);
            return run;
        }
        catch (GitHubException e)
        {
            repo.ConsecutiveFailures++;
            await FinishAsync(db, repo, run, "failed", e.Code, e.Message, ct);
            if (e.Transient) throw;
            return run;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            repo.ConsecutiveFailures++;
            log.LogError(e, "Sync of {Repo} failed", repo.FullName);
            await FinishAsync(db, repo, run, "failed", "internal", e.Message, ct);
            throw;
        }

        run.FinishedAt = clock.UtcNow;
        repo.LastSyncedAt = clock.UtcNow;
        repo.UpdatedAt = clock.UtcNow;
        repo.NextSyncAt = repo.State == RepoState.Active ? NextSync(repo) : null;
        await db.SaveChangesAsync(ct);
        if ((changed || reevaluate) && repo.State is RepoState.Active or RepoState.Paused)
            await RequestPublishAsync(ct);
        return run;
    }

    private DateTimeOffset NextSync(Repository repo)
    {
        var jitter = Random.Shared.NextDouble() * 0.2 - 0.1;
        var minutes = repo.ConsecutiveFailures >= 5 ? 360 : repo.SyncIntervalMinutes * (1 + jitter);
        return clock.UtcNow.AddMinutes(minutes);
    }

    private async Task FinishAsync(AppDbContext db, Repository repo, SyncRun run, string status, string category, string error, CancellationToken ct)
    {
        run.Status = status; run.ErrorCategory = category; run.Error = error.Length > 500 ? error[..500] : error; run.FinishedAt = clock.UtcNow;
        repo.LastSyncStatus = status; repo.UpdatedAt = clock.UtcNow;
        if (repo.State == RepoState.Active)
            repo.NextSyncAt = category == "rate_limited" ? clock.UtcNow.AddMinutes(5) : NextSync(repo);
        await db.SaveChangesAsync(CancellationToken.None);
    }

    public async Task RequestPublishAsync(CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var suites = await db.AptSuites.Where(s => s.IsEnabled).Select(s => s.Id).ToListAsync(ct);
        foreach (var id in suites)
            await jobs.EnqueueAsync(JobKind.PublishSuite, new { suiteId = id }, $"publish:{id}", TimeSpan.FromSeconds(5), ct: ct);
    }

    private async Task<string[]> AllowListAsync(CancellationToken ct) =>
        await settings.GetAsync<string[]>(SettingsService.ArchAllowList, ct) ?? Architectures.ParseList(apt.Value.Architectures);

    private static void ApplyMetadata(Repository repo, GhRepo meta)
    {
        repo.Owner = meta.Owner; repo.Name = meta.Name; repo.FullName = meta.FullName; repo.HtmlUrl = meta.HtmlUrl;
        repo.Description = meta.Description; repo.LicenseSpdx = meta.License; repo.DefaultBranch = meta.DefaultBranch;
        repo.IsArchived = meta.Archived;
    }

    private async Task<bool> ProcessReleaseAsync(AppDbContext db, Repository repo, GhRelease rel, SyncRun run, bool reevaluate,
        PackagePolicy policy, string[] allow, CancellationToken ct)
    {
        var changed = false;
        var row = await db.Releases.FirstOrDefaultAsync(r => r.RepositoryId == repo.Id && r.GithubReleaseId == rel.Id, ct);
        if (row is null)
        {
            row = new Release { Id = Ids.New(), RepositoryId = repo.Id, GithubReleaseId = rel.Id, ObservedAt = clock.UtcNow };
            db.Releases.Add(row);
        }
        var flipped = row.Id != default && row.IsPrerelease != rel.Prerelease && db.Entry(row).State != EntityState.Added;
        row.TagName = rel.Tag; row.Name = rel.Name; row.Body = rel.Body; row.IsPrerelease = rel.Prerelease; row.IsDraft = false;
        row.PublishedAt = rel.PublishedAt; row.HtmlUrl = rel.HtmlUrl; row.DownloadCountTotal = rel.Assets.Sum(a => a.DownloadCount);
        row.ObservedAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);

        if (flipped)
        {
            var channel = rel.Prerelease ? "prerelease" : "stable";
            var variantIds = await (from s in db.PackageSources
                                    join a in db.ReleaseAssets on s.AssetId equals a.Id
                                    where a.ReleaseId == row.Id && s.IsWinner
                                    select s.VariantId).ToListAsync(ct);
            if (variantIds.Count > 0)
            {
                await db.PackageVariants.Where(v => variantIds.Contains(v.Id)).ExecuteUpdateAsync(s => s.SetProperty(v => v.Channel, channel), ct);
                changed = true;
            }
        }

        if (rel.Prerelease && !repo.IncludePrereleases) return changed;

        var maxBytes = Math.Min(repo.MaxAssetBytes ?? long.MaxValue, ghOpt.Value.MaxAssetBytes);
        foreach (var asset in rel.Assets)
        {
            if (!GlobMatcher.IsMatch(repo.AssetIncludeGlob, asset.Name)) continue;
            if (repo.AssetExcludeGlob is { Length: > 0 } ex && GlobMatcher.IsMatch(ex, asset.Name)) continue;
            run.AssetsSeen++;
            var ar = await db.ReleaseAssets.FirstOrDefaultAsync(a => a.GithubAssetId == asset.Id, ct);
            if (ar is null)
            {
                ar = new ReleaseAsset { Id = Ids.New(), ReleaseId = row.Id, GithubAssetId = asset.Id, ObservedAt = clock.UtcNow };
                db.ReleaseAssets.Add(ar);
            }
            else
            {
                if (ar.State is AssetState.Parsed or AssetState.Quarantined)
                {
                    ar.DownloadCount = asset.DownloadCount;
                    // a repository that became publishable again revives variants tombstoned while it was ineligible
                    var src = await db.PackageSources.FirstOrDefaultAsync(x => x.AssetId == ar.Id, ct);
                    if (src is not null && repo.State is RepoState.Active or RepoState.Paused)
                    {
                        var tv = await db.PackageVariants.FirstAsync(x => x.Id == src.VariantId, ct);
                        if (tv.State == VariantState.Tombstoned && tv.QuarantineReason == TombReason.RepoIneligible)
                        {
                            await arbitration.ReviveAsync(db, tv, src, ct);
                            await db.SaveChangesAsync(ct);
                            changed = true;
                        }
                    }
                    continue;
                }
                if (ar.State == AssetState.Excluded && ar.ExcludedReason is "not_deb" or TombReason.Retention or TombReason.AdminDeleted) continue;
                if (ar.State == AssetState.Excluded && ar.ExcludedReason is { } er && er.StartsWith("arch_not_selected:", StringComparison.Ordinal))
                {
                    var arch = er["arch_not_selected:".Length..];
                    if (!repo.Architectures.Contains(arch)) { run.AssetsExcluded++; continue; }
                }
                if (ar.State == AssetState.Failed && ar.FailureReason is { } fr && PermanentFailures.Contains(fr) && ar.SizeBytes == asset.Size
                    && ar.DigestSha256 == asset.DigestSha256) { run.AssetsFailed++; continue; }
            }
            ar.Name = asset.Name; ar.SizeBytes = asset.Size; ar.ContentType = asset.ContentType; ar.DigestSha256 = asset.DigestSha256;
            ar.DownloadCount = asset.DownloadCount; ar.SourceUrl = asset.Url; ar.ObservedAt = clock.UtcNow;
            ar.FailureReason = null; ar.ExcludedReason = null;
            if (asset.Size > maxBytes)
            {
                ar.State = AssetState.Failed; ar.FailureReason = "too_large"; run.AssetsFailed++;
                await db.SaveChangesAsync(ct);
                continue;
            }
            await db.SaveChangesAsync(ct);
            try
            {
                if (await IngestAsync(db, repo, row, ar, asset, maxBytes, run, policy, allow, ct)) changed = true;
            }
            catch (GitHubRateLimitedException) { throw; }
            catch (GitHubException e) when (e.Transient) { throw; }
            catch (GitHubException e)
            {
                ar.State = AssetState.Failed; ar.FailureReason = e.Code == "too_large" ? "too_large" : "download_failed";
                run.AssetsFailed++;
                await db.SaveChangesAsync(ct);
            }
        }
        return changed;
    }

    private async Task<bool> IngestAsync(AppDbContext db, Repository repo, Release rel, ReleaseAsset ar, GhAsset asset, long maxBytes,
        SyncRun run, PackagePolicy policy, string[] allow, CancellationToken ct)
    {
        var dl = await gh.DownloadAssetAsync(asset, maxBytes, blobs.TempDirectory, ct);
        var tempPath = dl.TempPath;
        try
        {
            if (asset.DigestSha256 is { Length: > 0 } expected &&
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(expected), System.Text.Encoding.ASCII.GetBytes(dl.Sha256)))
            {
                ar.State = AssetState.Failed; ar.FailureReason = "digest_mismatch"; run.AssetsFailed++;
                log.LogWarning("Digest mismatch for asset {Asset} of {Repo}", asset.Name, repo.FullName);
                await audit.WriteAsync("asset.digest_mismatch", null, "repository", repo.Id.ToString(), "failure", new { asset = asset.Name }, ct: ct);
                await db.SaveChangesAsync(ct);
                return false;
            }
            DebInfo info;
            await using (var fs = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                Span<byte> head = stackalloc byte[8];
                var n = fs.Read(head);
                if (n < 8 || !ArReader.HasMagic(head))
                {
                    ar.State = AssetState.Excluded; ar.ExcludedReason = "not_deb"; run.AssetsExcluded++;
                    await db.SaveChangesAsync(ct);
                    return false;
                }
                try { info = DebInspector.Inspect(fs, maxBytes); }
                catch (DebFormatException e)
                {
                    ar.State = AssetState.Failed; ar.FailureReason = e.Code; run.AssetsFailed++;
                    await db.SaveChangesAsync(ct);
                    return false;
                }
            }

            var c = info.Control;
            if (c.Architecture != "all" && !repo.Architectures.Contains(c.Architecture))
            {
                ar.State = AssetState.Excluded; ar.ExcludedReason = "arch_not_selected:" + c.Architecture; run.AssetsExcluded++;
                await db.SaveChangesAsync(ct);
                return false;
            }
            if (c.Architecture != "all" && !allow.Contains(c.Architecture))
            {
                ar.State = AssetState.Excluded; ar.ExcludedReason = "arch_not_allowed:" + c.Architecture; run.AssetsExcluded++;
                await db.SaveChangesAsync(ct);
                return false;
            }

            var verdict = policy.Evaluate(c);
            var now = clock.UtcNow;

            // blob (content addressed)
            var blob = await db.Blobs.FirstOrDefaultAsync(b => b.Sha256 == dl.Sha256, ct);
            if (blob is null)
            {
                var stored = await blobs.AdoptFileAsync(tempPath, dl.Sha256, dl.Sha512, dl.Size, ct);
                tempPath = "";
                blob = new Blob
                {
                    Id = Ids.New(),
                    Sha256 = stored.Sha256,
                    Sha512 = stored.Sha512,
                    SizeBytes = stored.Size,
                    StorageKey = stored.StorageKey,
                    ContentType = "application/vnd.debian.binary-package",
                    CreatedAt = now,
                    LastReferencedAt = now
                };
                db.Blobs.Add(blob);
            }
            else blob.LastReferencedAt = now;

            var package = await db.Packages.FirstOrDefaultAsync(p => p.NameLower == c.Package.ToLower(), ct);
            if (package is null)
            {
                package = new Package { Id = Ids.New(), Name = c.Package, FirstSeenAt = now };
                db.Packages.Add(package);
                await db.SaveChangesAsync(ct);
            }

            var variant = await db.PackageVariants.FirstOrDefaultAsync(v => v.PackageId == package.Id && v.Version == c.Version && v.Architecture == c.Architecture, ct);
            var channel = rel.IsPrerelease ? "prerelease" : "stable";
            DateTimeOffset? publishAfter = repo.HoldbackHours > 0 ? (rel.PublishedAt ?? now).AddHours(repo.HoldbackHours) : null;
            var created = false;

            if (variant is null)
            {
                variant = new PackageVariant
                {
                    Id = Ids.New(),
                    PackageId = package.Id,
                    Version = c.Version,
                    Architecture = c.Architecture,
                    Channel = channel,
                    Control = ControlJson.Serialize(c.Fields),
                    Description = c.Description,
                    SizeBytes = blob.SizeBytes,
                    Sha256 = blob.Sha256,
                    Sha512 = blob.Sha512,
                    BlobId = blob.Id,
                    State = verdict.Quarantine ? VariantState.Quarantined : VariantState.Active,
                    QuarantineReason = verdict.Reason,
                    PublishAfter = publishAfter,
                    FirstSeenAt = now
                };
                variant.Filename = await AllocateFilenameAsync(db, c, blob, ct);
                db.PackageVariants.Add(variant);
                await db.SaveChangesAsync(ct);
                db.PackageSources.Add(new PackageSource { Id = Ids.New(), VariantId = variant.Id, AssetId = ar.Id, RepositoryId = repo.Id, BlobId = blob.Id, IsWinner = true, CreatedAt = now });
                run.VariantsCreated++;
                created = true;
            }
            else if (variant.State == VariantState.Tombstoned)
            {
                await db.PackageSources.Where(s => s.VariantId == variant.Id && s.IsWinner).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsWinner, false), ct);
                variant.BlobId = blob.Id; variant.Sha256 = blob.Sha256; variant.Sha512 = blob.Sha512; variant.SizeBytes = blob.SizeBytes;
                variant.Control = ControlJson.Serialize(c.Fields); variant.Description = c.Description; variant.Channel = channel;
                variant.State = verdict.Quarantine ? VariantState.Quarantined : VariantState.Active; variant.QuarantineReason = verdict.Reason;
                variant.Filename = await AllocateFilenameAsync(db, c, blob, ct);
                variant.PublishAfter = publishAfter; variant.PublishedAt = null;
                db.PackageSources.Add(new PackageSource { Id = Ids.New(), VariantId = variant.Id, AssetId = ar.Id, RepositoryId = repo.Id, BlobId = blob.Id, IsWinner = true, CreatedAt = now });
                created = true;
            }
            else
            {
                var identical = variant.Sha256 == blob.Sha256;
                db.PackageSources.Add(new PackageSource { Id = Ids.New(), VariantId = variant.Id, AssetId = ar.Id, RepositoryId = repo.Id, BlobId = blob.Id, IsWinner = false, CreatedAt = now });
                if (!identical) run.ConflictsFound++;
            }

            ar.State = verdict.Quarantine ? AssetState.Quarantined : AssetState.Parsed;
            ar.FailureReason = verdict.Quarantine ? verdict.Reason : null;
            run.AssetsIngested++;
            await db.SaveChangesAsync(ct);
            return created;
        }
        finally
        {
            if (tempPath.Length > 0) try { File.Delete(tempPath); } catch { /* ignore */ }
        }
    }

    /// <summary>Allocates an immutable pool filename (INV-6) and records it in pool_files.</summary>
    internal static async Task<string> AllocateFilenameAsync(AppDbContext db, ControlFile c, Blob blob, CancellationToken ct)
    {
        string? suffixSource = null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var name = PoolNaming.FileName(c.Package, c.Version, c.Architecture, suffixSource);
            var existing = await db.PoolFiles.FirstOrDefaultAsync(p => p.Component == "main" && p.Filename == name, ct)
                           ?? db.PoolFiles.Local.FirstOrDefault(p => p.Component == "main" && p.Filename == name);
            if (existing is null)
            {
                db.PoolFiles.Add(new PoolFile { Component = "main", Filename = name, Sha256 = blob.Sha256, SizeBytes = blob.SizeBytes, CreatedAt = DateTimeOffset.UtcNow });
                return name;
            }
            if (existing.Sha256 == blob.Sha256) return name;
            suffixSource = blob.Sha256;
            if (attempt >= 1) suffixSource = blob.Sha256[(attempt * 2)..];
        }
        throw new InvalidOperationException("Could not allocate pool filename.");
    }
}
