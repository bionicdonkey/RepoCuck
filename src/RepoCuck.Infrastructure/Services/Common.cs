using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Services;

public static class Ids
{
    public static Guid New() => Guid.CreateVersion7();
}

public static class ControlJson
{
    public static string Serialize(IEnumerable<KeyValuePair<string, string>> fields)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            foreach (var (k, v) in fields) w.WriteString(k, v);
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }

    public static List<KeyValuePair<string, string>> Deserialize(string json)
    {
        var list = new List<KeyValuePair<string, string>>();
        using var doc = JsonDocument.Parse(json);
        foreach (var p in doc.RootElement.EnumerateObject()) list.Add(new(p.Name, p.Value.GetString() ?? ""));
        return list;
    }
}

public sealed class ServiceException(string code, string message, int status = 400, object? data = null) : Exception(message)
{
    public string Code { get; } = code;
    public int Status { get; } = status;
    public object? Extra { get; } = data;
}

public interface IAuditService
{
    Task WriteAsync(string action, Guid? actor, string? targetType, string? targetId, string outcome = "success",
        object? metadata = null, IPAddress? ip = null, string? correlationId = null, string? actorLabel = null, CancellationToken ct = default);
}

public sealed class AuditService(IDbContextFactory<AppDbContext> dbf, IClock clock) : IAuditService
{
    public async Task WriteAsync(string action, Guid? actor, string? targetType, string? targetId, string outcome = "success",
        object? metadata = null, IPAddress? ip = null, string? correlationId = null, string? actorLabel = null, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        db.AuditLog.Add(new AuditEntry
        {
            OccurredAt = clock.UtcNow, ActorUserId = actor, ActorLabel = actorLabel ?? (actor is null ? "system" : null),
            ActorIp = ip, Action = action, TargetType = targetType, TargetId = targetId, Outcome = outcome,
            Metadata = metadata is null ? "{}" : JsonSerializer.Serialize(metadata), CorrelationId = correlationId
        });
        await db.SaveChangesAsync(ct);
    }
}

public sealed class SettingsService(IDbContextFactory<AppDbContext> dbf, IClock clock)
{
    public async Task<T?> GetAsync<T>(string key, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var s = await db.Settings.AsNoTracking().FirstOrDefaultAsync(x => x.Key == key, ct);
        return s is null ? default : JsonSerializer.Deserialize<T>(s.Value);
    }

    public async Task SetAsync<T>(string key, T value, Guid? by, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var s = await db.Settings.FirstOrDefaultAsync(x => x.Key == key, ct);
        var json = JsonSerializer.Serialize(value);
        if (s is null) db.Settings.Add(new Setting { Key = key, Value = json, UpdatedAt = clock.UtcNow, UpdatedBy = by });
        else { s.Value = json; s.UpdatedAt = clock.UtcNow; s.UpdatedBy = by; }
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyDictionary<string, string>> AllAsync(CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Settings.AsNoTracking().ToDictionaryAsync(s => s.Key, s => s.Value, ct);
    }

    public const string ArchAllowList = "arch_allow_list";
    public const string ReservedNames = "reserved_names";
}
