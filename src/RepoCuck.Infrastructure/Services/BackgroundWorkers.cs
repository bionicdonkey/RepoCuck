using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

/// <summary>Claims and executes jobs with heartbeated leases.</summary>
public sealed class JobRunner(IServiceScopeFactory scopes, JobQueue queue, IOptions<JobsOptions> opt, IGitHubClient gh,
    ILogger<JobRunner> log) : BackgroundService
{
    private static readonly TimeSpan Lease = TimeSpan.FromMinutes(2);
    private readonly string _worker = $"{Environment.MachineName}:{Environment.ProcessId}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var slots = new SemaphoreSlim(Math.Max(1, opt.Value.WorkerConcurrency));
        var running = new List<Task>();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await slots.WaitAsync(stoppingToken);
                Job? job = null;
                if (gh.RateLimitRemainingPercent >= 10) job = await queue.ClaimAsync(_worker, Lease, stoppingToken);
                if (job is null)
                {
                    slots.Release();
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                    continue;
                }
                var t = Task.Run(async () =>
                {
                    try { await RunJobAsync(job, stoppingToken); }
                    finally { slots.Release(); }
                }, CancellationToken.None);
                lock (running) { running.RemoveAll(x => x.IsCompleted); running.Add(t); }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e)
            {
                log.LogError(e, "Job runner loop error");
                try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); } catch (OperationCanceledException) { break; }
            }
        }
        Task[] pending;
        lock (running) pending = running.ToArray();
        await Task.WhenAll(pending);
    }

    private async Task RunJobAsync(Job job, CancellationToken stop)
    {
        using var hb = CancellationTokenSource.CreateLinkedTokenSource(stop);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
        timeout.CancelAfter(TimeSpan.FromMinutes(30));
        var heart = Task.Run(async () =>
        {
            try
            {
                while (!hb.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(30), hb.Token);
                    await queue.HeartbeatAsync(job.Id, Lease, CancellationToken.None);
                }
            }
            catch (OperationCanceledException) { }
        });
        try
        {
            using var scope = scopes.CreateScope();
            await Dispatch(scope.ServiceProvider, job, timeout.Token);
            await queue.CompleteAsync(job.Id, CancellationToken.None);
        }
        catch (GitHubRateLimitedException e)
        {
            log.LogWarning("Job {Kind} deferred until {Reset}", job.Kind, e.ResetAt);
            await queue.FailAsync(job, "rate limited", (e.ResetAt - DateTimeOffset.UtcNow) + TimeSpan.FromSeconds(Random.Shared.Next(1, 30)), consumeAttempt: false, CancellationToken.None);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            await queue.FailAsync(job, "shutdown", TimeSpan.Zero, consumeAttempt: false, CancellationToken.None);
        }
        catch (Exception e)
        {
            log.LogError(e, "Job {Kind} {Id} failed", job.Kind, job.Id);
            await queue.FailAsync(job, e.Message, null, consumeAttempt: true, CancellationToken.None);
        }
        finally { hb.Cancel(); await heart; }
    }

    private static async Task Dispatch(IServiceProvider sp, Job job, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(job.Payload);
        var p = doc.RootElement;
        switch (job.Kind)
        {
            case JobKind.SyncRepository:
                await sp.GetRequiredService<SyncService>().SyncAsync(p.GetProperty("repositoryId").GetGuid(),
                    p.TryGetProperty("trigger", out var t) ? t.GetString() ?? "schedule" : "schedule",
                    p.TryGetProperty("reevaluate", out var r) && r.GetBoolean(), ct);
                break;
            case JobKind.PublishSuite:
                Guid? suite = p.TryGetProperty("suiteId", out var s) && s.ValueKind == JsonValueKind.String ? s.GetGuid() : null;
                await sp.GetRequiredService<PublisherService>().PublishAsync(suite, p.TryGetProperty("force", out var f) && f.GetBoolean(), ct);
                break;
            case JobKind.RebuildApt:
                await sp.GetRequiredService<PublisherService>().PublishAsync(null, true, ct);
                break;
            case JobKind.RefreshReleaseDates:
                await sp.GetRequiredService<PublisherService>().PublishAsync(null, true, ct);
                break;
            case JobKind.RetentionSweep:
                await sp.GetRequiredService<RetentionService>().SweepAsync(ct);
                break;
            default:
                throw new InvalidOperationException($"Unknown job kind {job.Kind}");
        }
    }
}

/// <summary>Enqueues due syncs, the daily Release heartbeat and nightly retention; sweeps expired leases.</summary>
public sealed class SchedulerService(IDbContextFactory<AppDbContext> dbf, JobQueue queue, IClock clock, ILogger<SchedulerService> log) : BackgroundService
{
    private DateTimeOffset _lastHeartbeat = DateTimeOffset.MinValue;
    private DateTimeOffset _lastRetention = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = clock.UtcNow;
                await queue.SweepExpiredLeasesAsync(ct);
                await using (var db = await dbf.CreateDbContextAsync(ct))
                {
                    var due = await db.Repositories.Where(r => r.State == RepoState.Active && r.NextSyncAt != null && r.NextSyncAt <= now)
                        .Select(r => r.Id).Take(200).ToListAsync(ct);
                    foreach (var id in due)
                        await queue.EnqueueAsync(JobKind.SyncRepository, new { repositoryId = id, trigger = "schedule", reevaluate = false }, $"sync:{id}", ct: ct);
                    // pending holdbacks that have matured
                    var matured = await db.PackageVariants.AnyAsync(v => v.State == VariantState.Active && v.PublishAfter != null && v.PublishAfter <= now && v.PublishedAt == null, ct);
                    if (matured)
                        foreach (var sid in await db.AptSuites.Where(s => s.IsEnabled).Select(s => s.Id).ToListAsync(ct))
                            await queue.EnqueueAsync(JobKind.PublishSuite, new { suiteId = sid }, $"publish:{sid}", ct: ct);
                }
                if (now - _lastHeartbeat > TimeSpan.FromHours(24) - TimeSpan.FromMinutes(5) || _lastHeartbeat == DateTimeOffset.MinValue)
                {
                    await queue.EnqueueAsync(JobKind.RefreshReleaseDates, new { force = true }, "heartbeat", ct: ct);
                    _lastHeartbeat = now;
                }
                if (now - _lastRetention > TimeSpan.FromHours(24))
                {
                    await queue.EnqueueAsync(JobKind.RetentionSweep, null, "retention", ct: ct);
                    _lastRetention = now;
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { log.LogError(e, "Scheduler error"); }
            try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch (OperationCanceledException) { break; }
        }
    }
}
