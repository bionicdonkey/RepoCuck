using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Web.Components;

public sealed record InstallStripModel(string BaseUrl, string[] Arches, string Fingerprint, int Packages, DateTimeOffset? IndexedAt, string Commands, bool Plain);

/// <summary>The "add this mirror to a machine" strip: the actual commands for this server, ready to copy.</summary>
public sealed class InstallStripViewComponent(IDbContextFactory<AppDbContext> dbf, ISigner signer, IOptions<AptOptions> apt,
    IOptions<SecurityOptions> sec, IOptions<AppOptions> app) : ViewComponent
{
    public static string BaseUrl(HttpContext ctx, AptOptions apt, SecurityOptions sec, AppOptions app)
    {
        var prefix = "/" + apt.PathPrefix.Trim('/');
        if (!string.IsNullOrEmpty(apt.PublicHost)) return $"{sec.PublicScheme}://{apt.PublicHost}{prefix}";
        if (!string.IsNullOrEmpty(app.BaseUrl)) return app.BaseUrl.TrimEnd('/') + prefix;
        return $"{ctx.Request.Scheme}://{ctx.Request.Host}{prefix}";
    }

    public static string Commands(string url, string[] arches)
    {
        var opts = (arches.Length > 0 ? $"arch={string.Join(',', arches)} " : "") + "signed-by=/etc/apt/keyrings/repocuck.gpg";
        return "sudo install -d -m 0755 /etc/apt/keyrings\n" +
               $"curl -fsSL {url}/repocuck.gpg | sudo tee /etc/apt/keyrings/repocuck.gpg >/dev/null\n" +
               $"echo \"deb [{opts}] {url} stable main\" | sudo tee /etc/apt/sources.list.d/repocuck.list\n" +
               "sudo apt-get update";
    }

    public async Task<IViewComponentResult> InvokeAsync()
    {
        var url = BaseUrl(HttpContext, apt.Value, sec.Value, app.Value);
        await using var db = await dbf.CreateDbContextAsync();
        var archs = (await db.Repositories.AsNoTracking().Where(r => r.State == RepoState.Active || r.State == RepoState.Paused).Select(r => r.Architectures).ToListAsync())
            .SelectMany(a => a).Distinct().Order().ToArray();
        var packages = await db.PackageVariants.CountAsync(v => v.State == VariantState.Active && v.PublishedAt != null);
        var indexedQuery = from c in db.AptCurrent
                           join g in db.AptGenerations on c.GenerationId equals g.Id
                           join s in db.AptSuites on c.SuiteId equals s.Id
                           where s.Name == "stable"
                           select g.ActivatedAt;
        var indexed = await indexedQuery.FirstOrDefaultAsync();
        var fpr = "";
        try { await signer.EnsureReadyAsync(HttpContext.RequestAborted); fpr = signer.Fingerprint; } catch { /* signing key not ready yet */ }
        var spaced = string.Join(' ', Enumerable.Range(0, (fpr.Length + 3) / 4).Select(i => fpr.Substring(i * 4, Math.Min(4, fpr.Length - i * 4))));
        return View(new InstallStripModel(url, archs, spaced, packages, indexed, Commands(url, archs), !sec.Value.IsHttps));
    }
}
