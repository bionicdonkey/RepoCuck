using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

public sealed class JobQueue(IDbContextFactory<AppDbContext> dbf, IClock clock)
{
    /// <summary>Enqueues a job; if a pending job with the same dedupe key exists it is reused (and pulled forward if sooner).</summary>
    public async Task<Guid> EnqueueAsync(string kind, object? payload = null, string? dedupeKey = null, TimeSpan? delay = null,
        int maxAttempts = 5, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = clock.UtcNow;
        var runAfter = now + (delay ?? TimeSpan.Zero);
        for (var i = 0; i < 3; i++)
        {
            if (dedupeKey is not null)
            {
                var existing = await db.Jobs.FirstOrDefaultAsync(j => j.DedupeKey == dedupeKey && j.State == JobState.Pending, ct);
                if (existing is not null)
                {
                    if (runAfter < existing.RunAfter) { existing.RunAfter = runAfter; existing.UpdatedAt = now; await db.SaveChangesAsync(ct); }
                    return existing.Id;
                }
            }
            var job = new Job
            {
                Id = Ids.New(),
                Kind = kind,
                Payload = JsonSerializer.Serialize(payload ?? new { }),
                DedupeKey = dedupeKey,
                State = JobState.Pending,
                MaxAttempts = maxAttempts,
                RunAfter = runAfter,
                CreatedAt = now,
                UpdatedAt = now
            };
            db.Jobs.Add(job);
            try { await db.SaveChangesAsync(ct); return job.Id; }
            catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: "23505" })
            {
                db.Entry(job).State = EntityState.Detached; // lost a race on the dedupe index; retry as reuse
            }
        }
        throw new InvalidOperationException("Could not enqueue job.");
    }

    public async Task<Job?> ClaimAsync(string worker, TimeSpan lease, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var rows = await db.Jobs.FromSqlInterpolated($"""
            update jobs set state='running', locked_by={worker}, locked_until=now()+{lease}::interval,
                            attempts=attempts+1, updated_at=now()
            where id = (
              select j.id from jobs j
              where j.state='pending' and j.run_after <= now()
                and not exists (select 1 from jobs r
                                where r.state='running' and r.dedupe_key = j.dedupe_key and j.dedupe_key is not null)
              order by j.run_after
              for update skip locked
              limit 1
            )
            returning *
            """).AsNoTracking().ToListAsync(ct);
        return rows.FirstOrDefault();
    }

    public async Task HeartbeatAsync(Guid id, TimeSpan lease, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        await db.Jobs.Where(j => j.Id == id && j.State == JobState.Running)
            .ExecuteUpdateAsync(s => s.SetProperty(j => j.LockedUntil, clock.UtcNow + lease), ct);
    }

    public async Task CompleteAsync(Guid id, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        await db.Jobs.Where(j => j.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(j => j.State, JobState.Succeeded).SetProperty(j => j.LockedBy, (string?)null)
                .SetProperty(j => j.LockedUntil, (DateTimeOffset?)null).SetProperty(j => j.UpdatedAt, clock.UtcNow), ct);
    }

    /// <summary>Failure with backoff, or dead when attempts are exhausted. <paramref name="consumeAttempt"/>=false for deferrals.</summary>
    public async Task FailAsync(Job job, string error, TimeSpan? retryIn, bool consumeAttempt, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var j = await db.Jobs.FirstAsync(x => x.Id == job.Id, ct);
        var attempts = consumeAttempt ? j.Attempts : Math.Max(0, j.Attempts - 1);
        var dead = consumeAttempt && attempts >= j.MaxAttempts;
        j.Attempts = attempts;
        j.State = dead ? JobState.Dead : JobState.Pending;
        j.LastError = error.Length > 1000 ? error[..1000] : error;
        j.LockedBy = null; j.LockedUntil = null;
        var backoff = retryIn ?? TimeSpan.FromSeconds(Math.Min(3600, 30 * Math.Pow(2, Math.Max(0, attempts - 1))));
        j.RunAfter = clock.UtcNow + backoff;
        j.UpdatedAt = clock.UtcNow;
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: "23505" })
        {
            // another pending job with the same key already exists; this one is redundant
            db.Entry(j).State = EntityState.Detached;
            await using var db2 = await dbf.CreateDbContextAsync(ct);
            await db2.Jobs.Where(x => x.Id == job.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.State, JobState.Succeeded)
                .SetProperty(x => x.LockedBy, (string?)null).SetProperty(x => x.LockedUntil, (DateTimeOffset?)null), ct);
        }
    }

    /// <summary>Returns jobs whose lease expired to pending.</summary>
    public async Task<int> SweepExpiredLeasesAsync(CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var now = clock.UtcNow;
        var expired = await db.Jobs.Where(j => j.State == JobState.Running && j.LockedUntil < now).ToListAsync(ct);
        foreach (var j in expired)
        {
            j.State = j.Attempts >= j.MaxAttempts ? JobState.Dead : JobState.Pending;
            j.LockedBy = null; j.LockedUntil = null; j.RunAfter = now; j.LastError = "lease expired"; j.UpdatedAt = now;
        }
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { /* dedupe collision; try again next sweep */ }
        return expired.Count;
    }
}
