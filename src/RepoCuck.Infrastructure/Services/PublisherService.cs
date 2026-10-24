using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

public sealed record PublishOutcome(string Suite, bool Skipped, long GenerationNo, int PackageCount);

public sealed class PublisherService(
    IDbContextFactory<AppDbContext> dbf, NpgsqlDataSource ds, IBlobStore blobs, ISigner signer, IClock clock,
    ArbitrationService arbitration, SettingsService settings, IOptions<AptOptions> apt, IOptions<RetentionOptions> ret,
    ILogger<PublisherService> log)
{
    private static bool _xzWarned;

    public async Task<IReadOnlyList<PublishOutcome>> PublishAsync(Guid? suiteId, bool force, CancellationToken ct)
    {
        await using var lockConn = await ds.OpenConnectionAsync(ct);
        await using (var l = new NpgsqlCommand("select pg_advisory_lock(hashtext('repocuck:apt-publish'))", lockConn)) await l.ExecuteNonQueryAsync(ct);
        try
        {
            await signer.EnsureReadyAsync(ct);
            await using var db = await dbf.CreateDbContextAsync(ct);
            await arbitration.PromoteIneligibleAsync(db, ct);
            var suites = await db.AptSuites.Where(s => s.IsEnabled && (suiteId == null || s.Id == suiteId)).ToListAsync(ct);
            var results = new List<PublishOutcome>();
            foreach (var suite in suites) results.Add(await PublishSuiteAsync(db, suite, force, ct));
            return results;
        }
        finally
        {
            await using var u = new NpgsqlCommand("select pg_advisory_unlock(hashtext('repocuck:apt-publish'))", lockConn);
            await u.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }

    private sealed record Built(string Path, byte[] Data, string Sha256);

    private async Task<PublishOutcome> PublishSuiteAsync(AppDbContext db, AptSuite suite, bool force, CancellationToken ct)
    {
        var now = clock.UtcNow;
        var grace = TimeSpan.FromDays(ret.Value.OrphanGraceDays);
        var allow = await settings.GetAsync<string[]>(SettingsService.ArchAllowList, ct) ?? Architectures.ParseList(apt.Value.Architectures);

        var repos = (await db.Repositories.AsNoTracking()
            .Where(r => r.State == RepoState.Active || r.State == RepoState.Paused || r.State == RepoState.Removed).ToListAsync(ct))
            .Where(r => ArbitrationService.IsPublishable(r, now, grace)).ToList();
        var effective = repos.SelectMany(r => r.Architectures).Where(allow.Contains).Distinct().Order(StringComparer.Ordinal).ToList();
        var advertised = effective.Append("all").ToList();

        var publishableIds = repos.Select(r => r.Id).ToList();
        var rows = await (from v in db.PackageVariants.AsNoTracking()
                          join p in db.Packages.AsNoTracking() on v.PackageId equals p.Id
                          join s in db.PackageSources.AsNoTracking() on v.Id equals s.VariantId
                          where s.IsWinner && v.State == VariantState.Active && (v.PublishAfter == null || v.PublishAfter <= now)
                                && publishableIds.Contains(s.RepositoryId)
                                && (v.Channel == "stable" || suite.IncludePrereleases)
                          select new { v, p.Name, s.RepositoryId }).ToListAsync(ct);
        var repoArch = repos.ToDictionary(r => r.Id, r => r.Architectures);

        var built = new List<Built>();
        var publishedVariantIds = new HashSet<Guid>();
        foreach (var arch in advertised)
        {
            var sel = rows.Where(x => arch == "all"
                    ? x.v.Architecture == "all"
                    : (x.v.Architecture == arch && repoArch[x.RepositoryId].Contains(arch)) || x.v.Architecture == "all")
                .OrderBy(x => x.Name, StringComparer.Ordinal)
                .ThenBy(x => DebianVersion.Parse(x.v.Version))
                .ThenBy(x => x.v.Architecture, StringComparer.Ordinal).ToList();
            var dup = sel.GroupBy(x => (x.Name, x.v.Version, x.v.Architecture)).FirstOrDefault(g => g.Count() > 1);
            if (dup is not null) throw new InvalidOperationException($"Duplicate package identity in index: {dup.Key}");
            foreach (var x in sel) publishedVariantIds.Add(x.v.Id);
            var stanzas = sel.Select(x => new PackageStanza(ControlJson.Deserialize(x.v.Control),
                PoolNaming.RelativePath("main", x.Name, x.v.Filename), x.v.SizeBytes, x.v.Sha256, x.v.Sha512));
            var packages = PackagesWriter.Write(stanzas);
            var dir = $"main/binary-{arch}";
            built.Add(Make($"{dir}/Packages", packages));
            built.Add(Make($"{dir}/Packages.gz", Gzip(packages)));
            var xz = await XzAsync(packages, ct);
            if (xz is not null) built.Add(Make($"{dir}/Packages.xz", xz));
            // per-arch Release needs the generation number, so it's added after numbering below
        }

        // Skip if nothing changed and the current generation is recent.
        var current = await (from c in db.AptCurrent.AsNoTracking()
                             join g in db.AptGenerations.AsNoTracking() on c.GenerationId equals g.Id
                             where c.SuiteId == suite.Id select g).FirstOrDefaultAsync(ct);
        if (current is not null && !force && now - (current.ActivatedAt ?? current.CreatedAt) < TimeSpan.FromHours(12))
        {
            var old = await db.AptGenerationFiles.AsNoTracking().Where(f => f.GenerationId == current.Id && f.Path.EndsWith("/Packages"))
                .ToDictionaryAsync(f => f.Path, f => f.Sha256, ct);
            var neu = built.Where(b => b.Path.EndsWith("/Packages", StringComparison.Ordinal)).ToDictionary(b => b.Path, b => b.Sha256);
            if (old.Count == neu.Count && old.All(kv => neu.TryGetValue(kv.Key, out var h) && h == kv.Value))
                return new PublishOutcome(suite.Name, true, current.GenerationNo, current.PackageCount);
        }

        var genNo = (await db.AptGenerations.Where(g => g.SuiteId == suite.Id).MaxAsync(g => (long?)g.GenerationNo, ct) ?? 0) + 1;
        foreach (var arch in advertised)
            built.Add(Make($"main/binary-{arch}/Release", ReleaseWriter.WriteArchRelease(suite.Origin, suite.Label, suite.Name, genNo, suite.Component, arch)));

        var files = built.Select(b => new ReleaseFile(b.Path, b.Sha256, b.Data.Length)).ToList();
        var release = ReleaseWriter.WriteRelease(suite.Origin, suite.Label, suite.Name, genNo, advertised, suite.Component,
            suite.Description, now, now.AddDays(suite.ValidUntilDays), suite.NotAutomatic, files);

        var gen = new AptGeneration { Id = Ids.New(), SuiteId = suite.Id, GenerationNo = genNo, Status = "building", CreatedAt = now,
            PackageCount = rows.Select(x => x.v.Id).Distinct().Count() };
        db.AptGenerations.Add(gen);
        await db.SaveChangesAsync(ct);
        try
        {
            var genFiles = new List<AptGenerationFile>();
            foreach (var b in built)
            {
                var blob = await StoreIndexBlobAsync(db, b.Data, ct);
                genFiles.Add(new AptGenerationFile { GenerationId = gen.Id, Path = b.Path, BlobId = blob.Id, Sha256 = b.Sha256, SizeBytes = b.Data.Length });
                var d = b.Path[..b.Path.LastIndexOf('/')];
                genFiles.Add(new AptGenerationFile { GenerationId = gen.Id, Path = $"{d}/by-hash/SHA256/{b.Sha256}", BlobId = blob.Id, Sha256 = b.Sha256, SizeBytes = b.Data.Length });
            }
            var sig = await signer.SignAsync(release, ct);
            var relBlob = await StoreIndexBlobAsync(db, release, ct);
            var inBlob = await StoreIndexBlobAsync(db, sig.InRelease, ct);
            var gpgBlob = await StoreIndexBlobAsync(db, sig.ReleaseGpg, ct);
            genFiles.Add(new AptGenerationFile { GenerationId = gen.Id, Path = "Release", BlobId = relBlob.Id, Sha256 = relBlob.Sha256, SizeBytes = relBlob.SizeBytes });
            genFiles.Add(new AptGenerationFile { GenerationId = gen.Id, Path = "InRelease", BlobId = inBlob.Id, Sha256 = inBlob.Sha256, SizeBytes = inBlob.SizeBytes });
            genFiles.Add(new AptGenerationFile { GenerationId = gen.Id, Path = "Release.gpg", BlobId = gpgBlob.Id, Sha256 = gpgBlob.Sha256, SizeBytes = gpgBlob.SizeBytes });
            // de-duplicate by path (identical blobs can map to the same by-hash path)
            foreach (var f in genFiles.GroupBy(f => f.Path).Select(g => g.First())) db.AptGenerationFiles.Add(f);
            gen.ReleaseBlobId = relBlob.Id; gen.InreleaseBlobId = inBlob.Id; gen.ReleaseGpgBlobId = gpgBlob.Id;
            await db.SaveChangesAsync(ct);

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            if (current is not null)
                await db.AptGenerations.Where(g => g.Id == current.Id).ExecuteUpdateAsync(s => s.SetProperty(g => g.Status, "superseded"), ct);
            gen.Status = "signed"; gen.ActivatedAt = clock.UtcNow;
            var cur = await db.AptCurrent.FirstOrDefaultAsync(c => c.SuiteId == suite.Id, ct);
            if (cur is null) db.AptCurrent.Add(new AptCurrent { SuiteId = suite.Id, GenerationId = gen.Id, UpdatedAt = clock.UtcNow });
            else { cur.GenerationId = gen.Id; cur.UpdatedAt = clock.UtcNow; }
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }
        catch
        {
            await db.AptGenerations.Where(g => g.Id == gen.Id).ExecuteUpdateAsync(s => s.SetProperty(g => g.Status, "failed"), CancellationToken.None);
            throw;
        }

        if (publishedVariantIds.Count > 0)
        {
            var ids = publishedVariantIds.ToList();
            await db.PackageVariants.Where(v => ids.Contains(v.Id) && v.PublishedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(v => v.PublishedAt, now), ct);
        }
        // holdback: wake up when the next held-back variant becomes publishable
        log.LogInformation("Published {Suite} generation {No} ({Count} packages, archs {Archs})", suite.Name, genNo, gen.PackageCount, string.Join(',', advertised));
        return new PublishOutcome(suite.Name, false, genNo, gen.PackageCount);
    }

    public async Task<DateTimeOffset?> NextHoldbackAsync(CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = clock.UtcNow;
        return await db.PackageVariants.Where(v => v.State == VariantState.Active && v.PublishAfter > now).MinAsync(v => v.PublishAfter, ct);
    }

    private async Task<Blob> StoreIndexBlobAsync(AppDbContext db, byte[] data, CancellationToken ct)
    {
        var stored = await blobs.PutAsync(data, ct);
        var blob = await db.Blobs.FirstOrDefaultAsync(b => b.Sha256 == stored.Sha256, ct)
                   ?? db.Blobs.Local.FirstOrDefault(b => b.Sha256 == stored.Sha256);
        if (blob is null)
        {
            blob = new Blob { Id = Ids.New(), Sha256 = stored.Sha256, Sha512 = stored.Sha512, SizeBytes = stored.Size, StorageKey = stored.StorageKey,
                ContentType = "application/octet-stream", IsIndex = true, CreatedAt = clock.UtcNow, LastReferencedAt = clock.UtcNow };
            db.Blobs.Add(blob);
            await db.SaveChangesAsync(ct);
        }
        else blob.LastReferencedAt = clock.UtcNow;
        return blob;
    }

    private static Built Make(string path, byte[] data) => new(path, data, Convert.ToHexStringLower(SHA256.HashData(data)));

    private static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.SmallestSize, true)) gz.Write(data);
        return ms.ToArray();
    }

    private async Task<byte[]?> XzAsync(byte[] data, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo("xz") { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
            foreach (var a in new[] { "-6e", "-c", "-T1" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            var output = new MemoryStream();
            var read = p.StandardOutput.BaseStream.CopyToAsync(output, ct);
            await p.StandardInput.BaseStream.WriteAsync(data, ct);
            p.StandardInput.Close();
            await read;
            await p.WaitForExitAsync(ct);
            return p.ExitCode == 0 ? output.ToArray() : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            if (!_xzWarned) { _xzWarned = true; log.LogWarning("xz binary not found; Packages.xz will not be published."); }
            return null;
        }
    }
}
