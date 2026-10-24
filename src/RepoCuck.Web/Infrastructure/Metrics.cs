using System.Diagnostics.Metrics;
using System.Text;

namespace RepoCuck.Web.Infrastructure;

/// <summary>Small in-process counters rendered in Prometheus text format at /metrics.</summary>
public sealed class Metrics
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _counters = new();
    public void Inc(string name, string? label = null) => _counters.AddOrUpdate(label is null ? name : $"{name}{{{label}}}", 1, (_, v) => v + 1);

    public string Render(IEnumerable<(string Name, double Value)> gauges)
    {
        var sb = new StringBuilder();
        foreach (var (k, v) in _counters.OrderBy(x => x.Key)) sb.Append(k).Append(' ').Append(v).Append('\n');
        foreach (var (n, v) in gauges) sb.Append(n).Append(' ').Append(v.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
        return sb.ToString();
    }
}
