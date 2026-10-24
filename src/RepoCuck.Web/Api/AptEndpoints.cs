using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Web.Infrastructure;

namespace RepoCuck.Web.Api;

public static partial class AptEndpoints
{
    [GeneratedRegex("^[a-z0-9][a-z0-9+._~-]*\\.deb$")] private static partial Regex PoolFile();
    [GeneratedRegex("^[a-z0-9][a-z0-9+._-]*$")] private static partial Regex PoolDir();
    [GeneratedRegex("^[A-Za-z0-9._/-]+$")] private static partial Regex DistPath();
    [GeneratedRegex("^[0-9a-f]{64}$")] private static partial Regex Hex64();

    public static void MapAptEndpoints(this IEndpointRouteBuilder app, string prefix)
    {
        prefix = "/" + prefix.Trim('/');
        var g = app.MapGroup(prefix).AllowAnonymous().RequireRateLimiting("apt");

        g.MapMethods("/", ["GET", "HEAD"], Landing);
        g.MapMethods("/repocuck.gpg", ["GET", "HEAD"], async (HttpContext ctx, ISigner signer, CancellationToken ct) =>
            Key(ctx, await signer.ExportPublicKeyAsync(ct), "application/pgp-keys"));
        g.MapMethods("/repocuck.asc", ["GET", "HEAD"], async (HttpContext ctx, ISigner signer, CancellationToken ct) =>
            Key(ctx, await signer.ExportPublicKeyArmoredAsync(ct), "application/pgp-keys"));
        g.MapMethods("/dists/{suite}/{**rest}", ["GET", "HEAD"], Dists);
        g.MapMethods("/pool/{component}/{prefix}/{package}/{file}", ["GET", "HEAD"], Pool);
    }

    private static IResult Key(HttpContext ctx, byte[] data, string type)
    {
        ctx.Response.Headers.CacheControl = "public, max-age=3600";
        return Results.File(data, type);
    }

    private static string ContentTypeFor(string path) =>
        path.EndsWith(".gz", StringComparison.Ordinal) ? "application/gzip"
        : path.EndsWith(".xz", StringComparison.Ordinal) ? "application/x-xz"
        : path.EndsWith("Release.gpg", StringComparison.Ordinal) ? "application/pgp-signature"
        : "text/plain; charset=utf-8";

    private static async Task<IResult> Dists(HttpContext ctx, string suite, string rest, IDbContextFactory<AppDbContext> dbf, IBlobStore blobs, Metrics metrics, CancellationToken ct)
    {
        if (rest.Contains("..") || rest.Length > 300 || !DistPath().IsMatch(rest) || suite.Length > 20)
            return Problems.Result(ctx, 404, "not_found", "Not found");
        await using var db = await dbf.CreateDbContextAsync(ct);
        var s = await db.AptSuites.AsNoTracking().FirstOrDefaultAsync(x => x.Name == suite && x.IsEnabled, ct);
        if (s is null) { metrics.Inc("repocuck_apt_requests_total", "kind=\"index\",status=\"404\""); return Problems.Result(ctx, 404, "not_found", "Not found"); }

        var byHash = rest.Contains("/by-hash/SHA256/", StringComparison.Ordinal);
        if (byHash && !Hex64().IsMatch(rest[(rest.LastIndexOf('/') + 1)..]))
            return Problems.Result(ctx, 404, "not_found", "Not found");

        var q = from f in db.AptGenerationFiles.AsNoTracking()
                join gen in db.AptGenerations.AsNoTracking() on f.GenerationId equals gen.Id
                join b in db.Blobs.AsNoTracking() on f.BlobId equals b.Id
                where gen.SuiteId == s.Id && f.Path == rest
                select new { f.Sha256, b.StorageKey, b.SizeBytes, gen.GenerationNo, gen.CreatedAt, gen.Id };
        if (byHash) q = q.OrderByDescending(x => x.GenerationNo);
        else
        {
            var currentId = await db.AptCurrent.AsNoTracking().Where(c => c.SuiteId == s.Id).Select(c => c.GenerationId).FirstOrDefaultAsync(ct);
            q = q.Where(x => x.Id == currentId);
        }
        var hit = await q.FirstOrDefaultAsync(ct);
        if (hit is null || !blobs.Exists(hit.StorageKey)) { metrics.Inc("repocuck_apt_requests_total", "kind=\"index\",status=\"404\""); return Problems.Result(ctx, 404, "not_found", "Not found"); }
        ctx.Response.Headers.CacheControl = byHash ? "public, max-age=31536000, immutable" : "no-cache";
        metrics.Inc("repocuck_apt_requests_total", "kind=\"index\",status=\"200\"");
        return Results.File(blobs.OpenRead(hit.StorageKey), ContentTypeFor(rest), null, hit.CreatedAt, new EntityTagHeaderValue($"\"sha256:{hit.Sha256}\""), enableRangeProcessing: false);
    }

    private static async Task<IResult> Pool(HttpContext ctx, string component, string prefix, string package, string file,
        IDbContextFactory<AppDbContext> dbf, IBlobStore blobs, Metrics metrics, CancellationToken ct)
    {
        if (component != "main" || !PoolDir().IsMatch(prefix) || !PoolDir().IsMatch(package) || !PoolFile().IsMatch(file) || file.Length > 200)
            return Problems.Result(ctx, 404, "not_found", "Not found");
        await using var db = await dbf.CreateDbContextAsync(ct);
        var hit = await (from v in db.PackageVariants.AsNoTracking()
                         join p in db.Packages.AsNoTracking() on v.PackageId equals p.Id
                         join b in db.Blobs.AsNoTracking() on v.BlobId equals b.Id
                         where v.Filename == file && v.State != VariantState.Quarantined && p.NameLower == package
                         select new { v.Sha256, v.FirstSeenAt, b.StorageKey }).FirstOrDefaultAsync(ct);
        if (hit is null || !blobs.Exists(hit.StorageKey) || RepoCuck.Debian.PoolNaming.Prefix(package) != prefix)
        { metrics.Inc("repocuck_apt_requests_total", "kind=\"pool\",status=\"404\""); return Problems.Result(ctx, 404, "not_found", "Not found"); }
        ctx.Response.Headers.CacheControl = "public, max-age=31536000, immutable";
        metrics.Inc("repocuck_apt_requests_total", "kind=\"pool\",status=\"200\"");
        return Results.File(blobs.OpenRead(hit.StorageKey), "application/vnd.debian.binary-package", null, hit.FirstSeenAt,
            new EntityTagHeaderValue($"\"sha256:{hit.Sha256}\""), enableRangeProcessing: true);
    }

    private static async Task<IResult> Landing(HttpContext ctx, IDbContextFactory<AppDbContext> dbf, ISigner signer, IOptions<AptOptions> apt,
        IOptions<SecurityOptions> sec, IOptions<AppOptions> app, CancellationToken ct)
    {
        var prefix = "/" + apt.Value.PathPrefix.Trim('/');
        var url = RepoCuck.Web.Components.InstallStripViewComponent.BaseUrl(ctx, apt.Value, sec.Value, app.Value);
        await using var db = await dbf.CreateDbContextAsync(ct);
        var suites = await db.AptSuites.AsNoTracking().Where(s => s.IsEnabled).Select(s => s.Name).ToListAsync(ct);
        var pkgQuery = from v in db.PackageVariants.AsNoTracking()
                       join p in db.Packages on v.PackageId equals p.Id
                       where v.State == VariantState.Active && v.PublishedAt != null
                       orderby p.Name
                       select new { p.Name, v.Version, v.Architecture, v.Description };
        var pkgs = await pkgQuery.Take(1000).ToListAsync(ct);
        string fpr = ""; DateTimeOffset? exp = null;
        try { await signer.EnsureReadyAsync(ct); fpr = signer.Fingerprint; exp = await signer.GetKeyExpiryAsync(ct); } catch { /* key not ready */ }
        var archs = (await db.Repositories.AsNoTracking().Where(r => r.State == RepoState.Active || r.State == RepoState.Paused).Select(r => r.Architectures).ToListAsync(ct))
            .SelectMany(a => a).Distinct().Order().ToArray();
        Func<string?, string> E = s => System.Net.WebUtility.HtmlEncode(s) ?? "";
        var nonce = ctx.Nonce();
        var opts = (archs.Length > 0 ? "arch=" + string.Join(',', archs) + " " : "") + "signed-by=/etc/apt/keyrings/repocuck.gpg";
        var keyCmd = $"sudo install -d -m 0755 /etc/apt/keyrings\ncurl -fsSL {url}/repocuck.gpg | sudo tee /etc/apt/keyrings/repocuck.gpg >/dev/null";
        var srcCmd = $"echo \"deb [{opts}] {url} stable main\" | sudo tee /etc/apt/sources.list.d/repocuck.list";
        var deb822 = $"Types: deb\nURIs: {url}\nSuites: stable\nComponents: main\n" + (archs.Length > 0 ? $"Architectures: {string.Join(' ', archs)}\n" : "") + "Signed-By: /etc/apt/keyrings/repocuck.gpg";
        var pin = "Package: *\nPin: release o=RepoCuck\nPin-Priority: 400";
        var updCmd = "sudo apt-get update\nsudo apt-get install <package>";
        var fprSpaced = string.Join(' ', Enumerable.Range(0, (fpr.Length + 3) / 4).Select(i => fpr.Substring(i * 4, Math.Min(4, fpr.Length - i * 4))));
        string Block(string id, string text) =>
            $"<div class=\"codeblock\"><pre id=\"{id}\" data-copy-text=\"{E(text)}\"><code>{E(text)}</code></pre>" +
            $"<button type=\"button\" class=\"copy secondary sm\" data-copy-target=\"#{id}\" hidden><svg class=\"i\" aria-hidden=\"true\"><use href=\"#i-copy\"/></svg><span class=\"label\">Copy</span></button></div>";

        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\">");
        sb.Append("<title>Install packages from this mirror - RepoCuck</title><link rel=\"preload\" href=\"/fonts/bricolage-grotesque.woff2\" as=\"font\" type=\"font/woff2\" crossorigin><link rel=\"icon\" href=\"/favicon.svg\" type=\"image/svg+xml\"><link rel=\"stylesheet\" href=\"/css/site.css\"></head><body>");
        sb.Append("<svg width=\"0\" height=\"0\" class=\"sr-only\" aria-hidden=\"true\" focusable=\"false\"><defs><symbol id=\"i-copy\" viewBox=\"0 0 24 24\"><rect x=\"8\" y=\"8\" width=\"12\" height=\"12\" rx=\"2\"/><path d=\"M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2\"/></symbol><symbol id=\"i-search\" viewBox=\"0 0 24 24\"><circle cx=\"11\" cy=\"11\" r=\"6.5\"/><path d=\"m16 16 4 4\"/></symbol></defs></svg>");
        sb.Append("<div class=\"public\"><div class=\"top\"><a class=\"brand\" href=\"/\"><svg viewBox=\"0 0 32 32\" aria-hidden=\"true\"><rect class=\"mark-body\" width=\"32\" height=\"32\" rx=\"8\"/><path class=\"mark-line mark-hot\" d=\"M8 10.5h8\"/><path class=\"mark-line\" d=\"M8 16h16M8 21.5h11\"/></svg>RepoCuck</a>");
        sb.Append(ctx.User.Identity?.IsAuthenticated == true ? "<a class=\"btn secondary right\" href=\"/repos\">Open the dashboard</a>" : "<a class=\"btn secondary right\" href=\"/login\">Sign in</a>");
        sb.Append("</div><main id=\"main\"><div class=\"page-head\"><div class=\"titles\"><h1>Install packages from this mirror</h1>");
        sb.Append("<p class=\"lede\">A signed apt repository built from the release files of curated GitHub projects. Add it once; <code>apt</code> then installs and upgrades these packages like any other.</p></div></div>");
        sb.Append("<ol class=\"steps\">");
        sb.Append($"<li><h3>Trust the signing key</h3><p>Every index is signed. Save the key where apt can find it.</p>{Block("c-key", keyCmd)}");
        if (fpr.Length > 0) sb.Append($"<p class=\"muted\">The key fingerprint is <code>{E(fprSpaced)}</code>{(exp is null ? "" : $", valid until {exp:d MMM yyyy}")}. Compare it with <code>gpg --show-keys /etc/apt/keyrings/repocuck.gpg</code>. Also available as <a href=\"{E(prefix)}/repocuck.asc\">armored text</a>.</p>");
        sb.Append("</li>");
        sb.Append($"<li><h3>Add the repository</h3>{Block("c-src", srcCmd)}<details><summary>Prefer the deb822 format?</summary><p>Save this as <code>/etc/apt/sources.list.d/repocuck.sources</code> instead:</p>{Block("c-822", deb822)}</details></li>");
        sb.Append($"<li><h3>Prefer your distribution's own packages <span class=\"muted\">(recommended)</span></h3><p>This keeps a package here from silently replacing a distribution package of the same name. Packages the distribution doesn't have still install and upgrade. Save as <code>/etc/apt/preferences.d/repocuck</code>:</p>{Block("c-pin", pin)}</li>");
        sb.Append($"<li><h3>Update and install</h3>{Block("c-upd", updCmd)}");
        if (suites.Contains("testing")) sb.Append("<p class=\"muted\">Want prereleases too? Use <code>testing</code> instead of <code>stable</code> in the repository line.</p>");
        if (!sec.Value.IsHttps) sb.Append("<p class=\"muted\">This server is on plain HTTP. Package metadata is still signed and verified by apt.</p>");
        sb.Append("</li></ol>");
        sb.Append("<section class=\"section\" aria-labelledby=\"h-pk\"><div class=\"section-head\"><h2 id=\"h-pk\">Available packages</h2>");
        sb.Append($"<span class=\"muted\">{pkgs.Count}{(pkgs.Count == 1000 ? "+" : "")} published</span></div>");
        if (pkgs.Count == 0) sb.Append("<div class=\"empty\"><h3>Nothing is published yet</h3><p>Packages appear here once an administrator approves a repository.</p></div>");
        else
        {
            sb.Append("<div class=\"toolbar\"><div class=\"search\"><svg class=\"i\" aria-hidden=\"true\"><use href=\"#i-search\"/></svg><label class=\"sr-only\" for=\"pf\">Filter packages</label><input id=\"pf\" type=\"search\" placeholder=\"Filter packages\" data-filter=\"#pkgs tbody tr\" autocomplete=\"off\"></div></div>");
            sb.Append("<div class=\"tablewrap\"><table id=\"pkgs\"><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Description</th></tr></thead><tbody>");
            foreach (var p in pkgs) sb.Append($"<tr><td><strong>{E(p.Name)}</strong></td><td><span class=\"ver\">{E(p.Version)}</span></td><td>{E(p.Architecture)}</td><td>{E(p.Description.Split('\n')[0])}</td></tr>");
            sb.Append("</tbody></table></div>");
        }
        sb.Append("</section></main></div>");
        sb.Append($"<script src=\"/js/site.js\" nonce=\"{nonce}\"></script></body></html>");
        ctx.Response.Headers.CacheControl = "no-cache";
        return Results.Content(sb.ToString(), "text/html; charset=utf-8");
    }
}
