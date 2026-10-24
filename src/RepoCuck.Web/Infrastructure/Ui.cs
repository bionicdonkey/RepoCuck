using System.Net;
using Microsoft.AspNetCore.Html;

namespace RepoCuck.Web.Infrastructure;

/// <summary>Small rendering helpers shared by pages: status pills, icons, relative times and architecture tokens.</summary>
public static class Ui
{
    private static readonly Dictionary<string, (string Icon, string Label, string Css)> States = new(StringComparer.OrdinalIgnoreCase)
    {
        ["active"] = ("check-circle", "Active", "active"),
        ["proposed"] = ("hourglass", "Awaiting approval", "proposed"),
        ["pending"] = ("hourglass", "Pending", "pending"),
        ["paused"] = ("pause", "Paused", "paused"),
        ["removed"] = ("archive", "Removed", "removed"),
        ["rejected"] = ("x-circle", "Rejected", "rejected"),
        ["blocked"] = ("slash", "Blocked", "blocked"),
        ["approved"] = ("check-circle", "Approved", "active"),
        ["cancelled"] = ("x-circle", "Cancelled", "quiet"),
        ["succeeded"] = ("check-circle", "Succeeded", "active"),
        ["running"] = ("hourglass", "Running", "pending"),
        ["partial"] = ("alert", "Partial", "pending"),
        ["failed"] = ("x-circle", "Failed", "failed"),
        ["dead"] = ("x-circle", "Dead", "dead"),
        ["parsed"] = ("check-circle", "Ingested", "active"),
        ["discovered"] = ("hourglass", "Discovered", "paused"),
        ["excluded"] = ("slash", "Skipped", "quiet"),
        ["quarantined"] = ("shield", "Quarantined", "pending"),
        ["tombstoned"] = ("archive", "Retired", "quiet"),
        ["stale"] = ("alert", "Upstream unavailable", "pending"),
        ["enabled"] = ("check-circle", "Enabled", "active"),
        ["disabled"] = ("slash", "Disabled", "removed"),
    };

    public static IHtmlContent Icon(string name) =>
        new HtmlString($"<svg class=\"i\" aria-hidden=\"true\" focusable=\"false\"><use href=\"#i-{name}\"/></svg>");

    public static IHtmlContent Pill(string? state, string? label = null)
    {
        state ??= "";
        var (icon, text, css) = States.TryGetValue(state, out var s) ? s : ("info", Cap(state), "quiet");
        return new HtmlString($"<span class=\"pill pill-{css}\">{Icon(icon).ToHtml()}{WebUtility.HtmlEncode(label ?? text)}</span>");
    }

    public static string Cap(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..].Replace('_', ' ');

    public static IHtmlContent Arches(IEnumerable<string> enabled, IEnumerable<string>? all = null)
    {
        var on = enabled.ToList();
        var parts = on.Select(a => $"<span class=\"arch\">{WebUtility.HtmlEncode(a)}</span>");
        if (all is not null) parts = parts.Concat(all.Except(on).Select(a => $"<span class=\"arch off\" title=\"Not enabled\">{WebUtility.HtmlEncode(a)}</span>"));
        var html = string.Join("", parts);
        return new HtmlString(on.Count == 0 && all is null ? "<span class=\"muted\">none yet</span>" : $"<span class=\"arches\">{html}</span>");
    }

    public static string AgoText(DateTimeOffset? t, DateTimeOffset? now = null)
    {
        if (t is null) return "never";
        var d = (now ?? DateTimeOffset.UtcNow) - t.Value;
        if (d.TotalSeconds < 0) return "just now";
        if (d.TotalSeconds < 45) return "just now";
        if (d.TotalMinutes < 90) return $"{Math.Max(1, (int)Math.Round(d.TotalMinutes))} min ago";
        if (d.TotalHours < 36) return $"{(int)Math.Round(d.TotalHours)} h ago";
        if (d.TotalDays < 45) return $"{(int)Math.Round(d.TotalDays)} days ago";
        return t.Value.ToString("d MMM yyyy");
    }

    public static string UntilText(DateTimeOffset? t, DateTimeOffset? now = null)
    {
        if (t is null) return "not scheduled";
        var d = t.Value - (now ?? DateTimeOffset.UtcNow);
        if (d.TotalSeconds < 45) return "any moment now";
        if (d.TotalMinutes < 90) return $"in {Math.Max(1, (int)Math.Round(d.TotalMinutes))} min";
        if (d.TotalHours < 36) return $"in {(int)Math.Round(d.TotalHours)} h";
        return $"in {(int)Math.Round(d.TotalDays)} days";
    }

    /// <summary>A &lt;time&gt; element with a relative label and the exact timestamp as its tooltip.</summary>
    public static IHtmlContent Ago(DateTimeOffset? t) =>
        t is null ? new HtmlString("<span class=\"muted\">never</span>")
                  : new HtmlString($"<time datetime=\"{t.Value:O}\" title=\"{t.Value:yyyy-MM-dd HH:mm:ss} UTC\">{AgoText(t)}</time>");

    public static IHtmlContent Stamp(DateTimeOffset? t) =>
        t is null ? new HtmlString("") : new HtmlString($"<time datetime=\"{t.Value:O}\">{t.Value:yyyy-MM-dd HH:mm} UTC</time>");

    public static string ToHtml(this IHtmlContent c)
    {
        using var w = new StringWriter();
        c.WriteTo(w, HtmlEncoder);
        return w.ToString();
    }

    private static readonly System.Text.Encodings.Web.HtmlEncoder HtmlEncoder = System.Text.Encodings.Web.HtmlEncoder.Default;
}
