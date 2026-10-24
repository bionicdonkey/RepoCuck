using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;
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
        string baseUrl;
        if (!string.IsNullOrEmpty(apt.Value.PublicHost)) baseUrl = $"{sec.Value.PublicScheme}://{apt.Value.PublicHost}";
        else if (!string.IsNullOrEmpty(app.Value.BaseUrl)) baseUrl = app.Value.BaseUrl.TrimEnd('/');
        else baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
        var prefix = "/" + apt.Value.PathPrefix.Trim('/');
        await using var db = await dbf.CreateDbContextAsync(ct);
        var suites = await db.AptSuites.AsNoTracking().Where(s => s.IsEnabled).Select(s => s.Name).ToListAsync(ct);
        var pkgs = await (from v in db.PackageVariants.AsNoTracking() join p in db.Packages on v.PackageId equals p.Id
                          where v.State == VariantState.Active && v.PublishedAt != null
                          orderby p.Name select new { p.Name, v.Version, v.Architecture, v.Description }).Take(500).ToListAsync(ct);
        string fpr = ""; DateTimeOffset? exp = null;
        try { await signer.EnsureReadyAsync(ct); fpr = signer.Fingerprint; exp = await signer.GetKeyExpiryAsync(ct); } catch { /* key not ready */ }
        var archs = await db.Repositories.AsNoTracking().Where(r => r.State == RepoState.Active || r.State == RepoState.Paused).Select(r => r.Architectures).ToListAsync(ct);
        var archList = string.Join(",", archs.SelectMany(a => a).Distinct().Order());
        Func<string?, string> E = s => System.Net.WebUtility.HtmlEncode(s) ?? "";
        var sb = new StringBuilder();
        sb.Append($"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>RepoCuck APT repository</title><link rel=\"stylesheet\" href=\"/css/site.css\"></head><body><main class=\"container\">");
        sb.Append("<h1>RepoCuck APT repository</h1><p>Signed APT repository of curated GitHub release packages.</p>");
        sb.Append($"<h2>Add the repository</h2><pre>sudo install -d -m 0755 /etc/apt/keyrings\ncurl -fsSL {E(baseUrl)}{E(prefix)}/repocuck.gpg \\\n  | sudo tee /etc/apt/keyrings/repocuck.gpg &gt;/dev/null\necho \"deb [{(archList.Length > 0 ? "arch=" + E(archList) + " " : "")}signed-by=/etc/apt/keyrings/repocuck.gpg] \\\n{E(baseUrl)}{E(prefix)} stable main\" \\\n  | sudo tee /etc/apt/sources.list.d/repocuck.list\nsudo apt-get update</pre>");
        sb.Append("<h2>Recommended pin</h2><p>Keeps distribution packages preferred over same-named RepoCuck packages:</p><pre>sudo tee /etc/apt/preferences.d/repocuck &lt;&lt;'EOF'\nPackage: *\nPin: release o=RepoCuck\nPin-Priority: 400\nEOF</pre>");
        if (suites.Contains("testing")) sb.Append("<p>Prerelease builds are available as an opt-in: use <code>testing main</code> instead of <code>stable main</code>.</p>");
        sb.Append("<h2>Signing key</h2>");
        sb.Append($"<p>Fingerprint: <code>{E(fpr)}</code>{(exp is null ? "" : $" (expires {exp:yyyy-MM-dd})")}<br><a href=\"{E(prefix)}/repocuck.gpg\">repocuck.gpg</a> (binary) · <a href=\"{E(prefix)}/repocuck.asc\">repocuck.asc</a> (armored)</p>");
        sb.Append("<h2>Packages</h2><table><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Description</th></tr></thead><tbody>");
        foreach (var p in pkgs) sb.Append($"<tr><td>{E(p.Name)}</td><td>{E(p.Version)}</td><td>{E(p.Architecture)}</td><td>{E(p.Description.Split('\n')[0])}</td></tr>");
        sb.Append("</tbody></table></main></body></html>");
        ctx.Response.Headers.CacheControl = "no-cache";
        return Results.Content(sb.ToString(), "text/html; charset=utf-8");
    }
}
