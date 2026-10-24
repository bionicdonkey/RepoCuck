using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace RepoCuck.Infrastructure.Services;

/// <summary>Small in-process counters rendered in Prometheus text format at /metrics.</summary>
public sealed class Metrics
{
    private readonly ConcurrentDictionary<string, long> _counters = new();
    private readonly ConcurrentDictionary<string, (long Count, double Sum)> _summaries = new();

    public void Inc(string name, string? label = null, long by = 1) =>
        _counters.AddOrUpdate(label is null ? name : $"{name}{{{label}}}", by, (_, v) => v + by);

    public void Observe(string name, double seconds, string? label = null)
    {
        var key = label is null ? name : $"{name}|{label}";
        _summaries.AddOrUpdate(key, (1, seconds), (_, v) => (v.Count + 1, v.Sum + seconds));
    }

    public string Render(IEnumerable<(string Name, double Value)> gauges)
    {
        var sb = new StringBuilder();
        foreach (var (k, v) in _counters.OrderBy(x => x.Key, StringComparer.Ordinal)) sb.Append(k).Append(' ').Append(v).Append('\n');
        foreach (var (k, v) in _summaries.OrderBy(x => x.Key, StringComparer.Ordinal))
        {
            var parts = k.Split('|');
            var lbl = parts.Length > 1 ? $"{{{parts[1]}}}" : "";
            sb.Append(parts[0]).Append("_count").Append(lbl).Append(' ').Append(v.Count).Append('\n');
            sb.Append(parts[0]).Append("_sum").Append(lbl).Append(' ').Append(v.Sum.ToString("0.###", CultureInfo.InvariantCulture)).Append('\n');
        }
        foreach (var (n, v) in gauges) sb.Append(n).Append(' ').Append(v.ToString(CultureInfo.InvariantCulture)).Append('\n');
        return sb.ToString();
    }
}
