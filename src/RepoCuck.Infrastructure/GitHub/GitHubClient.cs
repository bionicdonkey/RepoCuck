using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.GitHub;

public sealed class GitHubClient : IGitHubClient
{
    public const string HttpClientName = "github";
    /// <summary>Base delay for 5xx/network retries (1s → 4s → 16s). Tests shrink this.</summary>
    public static TimeSpan BackoffBase { get; set; } = TimeSpan.FromSeconds(1);

    private readonly HttpClient _http;
    private readonly GitHubOptions _opt;
    private readonly IDbContextFactory<AppDbContext> _dbf;
    private readonly ILogger<GitHubClient> _log;
    private readonly string[] _allow;
    private readonly Uri _api;
    private volatile int _remainingPct = 100;

    public GitHubClient(IHttpClientFactory factory, IOptions<GitHubOptions> opt, IDbContextFactory<AppDbContext> dbf, ILogger<GitHubClient> log)
    {
        _http = factory.CreateClient(HttpClientName);
        _opt = opt.Value;
        _dbf = dbf;
        _log = log;
        _api = new Uri(_opt.ApiBaseUrl.TrimEnd('/') + "/");
        if (!_opt.AllowInsecureForTesting && _api.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("GitHub:ApiBaseUrl must be https.");
        _allow = _opt.AssetHostAllowList.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    public int RateLimitRemainingPercent => _remainingPct;

    /// <summary>Configures the SocketsHttpHandler: no auto-redirect and connect-time private IP rejection.</summary>
    public static SocketsHttpHandler CreateHandler(GitHubOptions opt)
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10), PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
        if (!opt.AllowInsecureForTesting)
        {
            handler.ConnectCallback = async (ctx, ct) =>
            {
                var addrs = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
                var ok = addrs.Where(a => !IsPrivate(a)).ToArray();
                if (ok.Length == 0) throw new HttpRequestException("Destination resolves to a non-public address.");
                var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try { await sock.ConnectAsync(new IPEndPoint(ok[0], ctx.DnsEndPoint.Port), ct); return new NetworkStream(sock, true); }
                catch { sock.Dispose(); throw; }
            };
        }
        return handler;
    }

    public static bool IsPrivate(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) return true;
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast) return true;
            var b6 = a.GetAddressBytes();
            return (b6[0] & 0xfe) == 0xfc; // ULA fc00::/7
        }
        var b = a.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254) || b[0] == 0 || (b[0] == 100 && b[1] is >= 64 and <= 127) || b[0] >= 224;
    }

    public async Task<GhRepo> GetRepoAsync(string owner, string name, CancellationToken ct) =>
        ParseRepo(await GetJsonAsync($"repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(name)}", ct));

    public async Task<GhRepo> GetRepoByIdAsync(long id, CancellationToken ct) =>
        ParseRepo(await GetJsonAsync($"repositories/{id}", ct));

    private static GhRepo ParseRepo(JsonElement e)
    {
        var priv = e.TryGetProperty("private", out var p) && p.GetBoolean();
        if (priv) throw new GitHubException("not_found", "Repository is not public.");
        var owner = e.GetProperty("owner").GetProperty("login").GetString()!;
        var name = e.GetProperty("name").GetString()!;
        string? lic = null;
        if (e.TryGetProperty("license", out var l) && l.ValueKind == JsonValueKind.Object && l.TryGetProperty("spdx_id", out var sp))
            lic = sp.GetString();
        return new GhRepo(e.GetProperty("id").GetInt64(), owner, name, e.GetProperty("full_name").GetString()!,
            e.GetProperty("html_url").GetString()!, Str(e, "description"), lic, Str(e, "default_branch"),
            e.TryGetProperty("archived", out var a) && a.GetBoolean(), priv);
    }

    private static string? Str(JsonElement e, string n) =>
        e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    public async Task<IReadOnlyList<GhRelease>> GetReleasesAsync(string owner, string name, int max, CancellationToken ct)
    {
        var result = new List<GhRelease>();
        string? next = $"repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(name)}/releases?per_page=100";
        for (var page = 0; next is not null && page < 20 && result.Count < max; page++)
        {
            var (json, link) = await GetJsonWithLinkAsync(next, ct);
            foreach (var r in json.EnumerateArray())
            {
                if (r.TryGetProperty("draft", out var d) && d.GetBoolean()) continue;
                var assets = new List<GhAsset>();
                if (r.TryGetProperty("assets", out var arr))
                    foreach (var a in arr.EnumerateArray())
                    {
                        string? digest = null;
                        var dg = Str(a, "digest");
                        if (dg is not null && dg.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) digest = dg[7..].ToLowerInvariant();
                        assets.Add(new GhAsset(a.GetProperty("id").GetInt64(), a.GetProperty("name").GetString()!,
                            a.GetProperty("size").GetInt64(), Str(a, "content_type"), digest,
                            a.TryGetProperty("download_count", out var dc) ? dc.GetInt64() : 0,
                            a.GetProperty("browser_download_url").GetString()!));
                    }
                DateTimeOffset? published = null;
                if (Str(r, "published_at") is { } ps && DateTimeOffset.TryParse(ps, out var pd)) published = pd;
                result.Add(new GhRelease(r.GetProperty("id").GetInt64(), r.GetProperty("tag_name").GetString()!, Str(r, "name"), Str(r, "body"),
                    r.TryGetProperty("prerelease", out var pr) && pr.GetBoolean(), false, published, Str(r, "html_url"), assets));
                if (result.Count >= max) break;
            }
            next = link;
        }
        return result;
    }

    private async Task<JsonElement> GetJsonAsync(string relative, CancellationToken ct) => (await GetJsonWithLinkAsync(relative, ct)).Json;

    private async Task<(JsonElement Json, string? Next)> GetJsonWithLinkAsync(string relative, CancellationToken ct)
    {
        var url = new Uri(_api, relative);
        var key = url.ToString();
        await using var db = await _dbf.CreateDbContextAsync(ct);
        var cached = await db.GithubCache.AsNoTracking().FirstOrDefaultAsync(c => c.CacheKey == key, ct);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                Decorate(req, true);
                if (cached?.Etag is not null) req.Headers.TryAddWithoutValidation("If-None-Match", cached.Etag);
                using var resp = await _http.SendAsync(req, ct);
                TrackRate(resp);
                if (resp.StatusCode == HttpStatusCode.NotModified && cached?.Payload is not null)
                    return (JsonDocument.Parse(cached.Payload).RootElement.Clone(), ParseNext(resp) ?? _links.GetValueOrDefault(key));
                if (resp.StatusCode == HttpStatusCode.NotFound) throw new GitHubException("not_found", "GitHub resource not found.");
                if (IsRateLimited(resp, out var reset)) throw new GitHubRateLimitedException(reset);
                if ((int)resp.StatusCode >= 500 || resp.StatusCode == HttpStatusCode.RequestTimeout)
                    throw new GitHubException("upstream", $"GitHub returned {(int)resp.StatusCode}", transient: true);
                if (!resp.IsSuccessStatusCode) throw new GitHubException("upstream", $"GitHub returned {(int)resp.StatusCode}");
                var body = await resp.Content.ReadAsStringAsync(ct);
                var link = ParseNext(resp);
                var etag = resp.Headers.ETag?.ToString();
                if (etag is not null)
                {
                    var wrapped = body;
                    await using var w = await _dbf.CreateDbContextAsync(ct);
                    var row = await w.GithubCache.FirstOrDefaultAsync(c => c.CacheKey == key, ct);
                    if (row is null) w.GithubCache.Add(new GithubCacheEntry { CacheKey = key, Etag = etag, Payload = wrapped, FetchedAt = DateTimeOffset.UtcNow });
                    else { row.Etag = etag; row.Payload = wrapped; row.FetchedAt = DateTimeOffset.UtcNow; }
                    try { await w.SaveChangesAsync(ct); } catch (DbUpdateException) { /* concurrent insert; ignore */ }
                    // Remember the Link header alongside the payload by re-fetching it on 304 (see NextLink).
                    _links[key] = link;
                }
                return (JsonDocument.Parse(body).RootElement.Clone(), link);
            }
            catch (Exception e) when (attempt < 3 && (e is HttpRequestException || e is TaskCanceledException && !ct.IsCancellationRequested || e is GitHubException { Transient: true } and not GitHubRateLimitedException))
            {
                var delay = TimeSpan.FromTicks(BackoffBase.Ticks * (long)Math.Pow(4, attempt));
                _log.LogWarning("GitHub request failed (attempt {Attempt}): {Message}", attempt + 1, e.Message);
                await Task.Delay(delay, ct);
            }
            catch (HttpRequestException e) { throw new GitHubException("upstream", e.Message, transient: true); }
        }
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string?> _links = new();

    private string? ParseNext(HttpResponseMessage resp)
    {
        if (!resp.Headers.TryGetValues("Link", out var vals)) return null;
        foreach (var part in string.Join(",", vals).Split(','))
        {
            var seg = part.Split(';');
            if (seg.Length < 2 || !seg[1].Contains("rel=\"next\"")) continue;
            var u = seg[0].Trim().Trim('<', '>');
            if (Uri.TryCreate(u, UriKind.Absolute, out var abs) && abs.Host == _api.Host)
                return abs.PathAndQuery.TrimStart('/');
        }
        return null;
    }

    private void Decorate(HttpRequestMessage req, bool api)
    {
        req.Headers.UserAgent.ParseAdd("RepoCuck/1.0");
        if (api)
        {
            req.Headers.Accept.ParseAdd("application/vnd.github+json");
            req.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
            if (!string.IsNullOrEmpty(_opt.Token)) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _opt.Token);
        }
    }

    private void TrackRate(HttpResponseMessage resp)
    {
        if (resp.Headers.TryGetValues("X-RateLimit-Remaining", out var r) && resp.Headers.TryGetValues("X-RateLimit-Limit", out var l)
            && int.TryParse(r.First(), out var rem) && int.TryParse(l.First(), out var lim) && lim > 0)
            _remainingPct = Math.Clamp(rem * 100 / lim, 0, 100);
    }

    private static bool IsRateLimited(HttpResponseMessage resp, out DateTimeOffset reset)
    {
        reset = DateTimeOffset.UtcNow.AddMinutes(1);
        if (resp.StatusCode is not (HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)) return false;
        if (resp.Headers.TryGetValues("Retry-After", out var ra) && int.TryParse(ra.First(), out var secs))
        { reset = DateTimeOffset.UtcNow.AddSeconds(secs); return true; }
        if (resp.Headers.TryGetValues("X-RateLimit-Remaining", out var rem) && rem.First() == "0")
        {
            if (resp.Headers.TryGetValues("X-RateLimit-Reset", out var rs) && long.TryParse(rs.First(), out var unix))
                reset = DateTimeOffset.FromUnixTimeSeconds(unix);
            return true;
        }
        return resp.StatusCode == HttpStatusCode.TooManyRequests;
    }

    public async Task<DownloadResult> DownloadAssetAsync(GhAsset asset, long maxBytes, string tempDir, CancellationToken ct)
    {
        Directory.CreateDirectory(tempDir);
        var uri = new Uri(asset.Url);
        for (var hop = 0; hop <= 5; hop++)
        {
            ValidateHop(uri);
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            Decorate(req, false);
            req.Headers.Accept.ParseAdd("application/octet-stream");
            if (uri.Host == _api.Host && !string.IsNullOrEmpty(_opt.Token))
                req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _opt.Token);
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            TrackRate(resp);
            if ((int)resp.StatusCode is 301 or 302 or 303 or 307 or 308)
            {
                var loc = resp.Headers.Location ?? throw new GitHubException("download", "Redirect without Location.");
                uri = loc.IsAbsoluteUri ? loc : new Uri(uri, loc);
                continue;
            }
            if (IsRateLimited(resp, out var reset)) throw new GitHubRateLimitedException(reset);
            if (resp.StatusCode == HttpStatusCode.NotFound) throw new GitHubException("not_found", "Asset gone.");
            if ((int)resp.StatusCode >= 500) throw new GitHubException("upstream", $"Asset host returned {(int)resp.StatusCode}", transient: true);
            if (!resp.IsSuccessStatusCode) throw new GitHubException("download", $"Asset download returned {(int)resp.StatusCode}");

            var declared = resp.Content.Headers.ContentLength;
            if (declared > maxBytes) throw new GitHubException("too_large", "Asset exceeds size cap.");
            var temp = Path.Combine(tempDir, Guid.NewGuid().ToString("N") + ".part");
            try
            {
                using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using var sha512 = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
                long total = 0;
                await using (var src = await resp.Content.ReadAsStreamAsync(ct))
                await using (var dst = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
                {
                    var buf = new byte[81920];
                    int n;
                    while (true)
                    {
                        using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        idle.CancelAfter(TimeSpan.FromSeconds(30));
                        n = await src.ReadAsync(buf, idle.Token);
                        if (n == 0) break;
                        total += n;
                        if (total > maxBytes) throw new GitHubException("too_large", "Asset exceeds size cap.");
                        sha256.AppendData(buf, 0, n);
                        sha512.AppendData(buf, 0, n);
                        await dst.WriteAsync(buf.AsMemory(0, n), ct);
                    }
                }
                if (declared is not null && declared != total) throw new GitHubException("size_mismatch", "Downloaded size differs from Content-Length.", transient: true);
                if (asset.Size > 0 && asset.Size != total) throw new GitHubException("size_mismatch", "Downloaded size differs from asset size.", transient: true);
                return new DownloadResult(temp, total, Convert.ToHexStringLower(sha256.GetHashAndReset()), Convert.ToHexStringLower(sha512.GetHashAndReset()));
            }
            catch
            {
                try { File.Delete(temp); } catch { /* ignore */ }
                throw;
            }
        }
        throw new GitHubException("download", "Too many redirects.");
    }

    private void ValidateHop(Uri uri)
    {
        if (!_opt.AllowInsecureForTesting && uri.Scheme != Uri.UriSchemeHttps)
            throw new GitHubException("download", "Non-https download hop refused.");
        if (!string.IsNullOrEmpty(uri.UserInfo)) throw new GitHubException("download", "User-info in URL refused.");
        var host = uri.Host;
        if (!_allow.Any(a => a.StartsWith("*.", StringComparison.Ordinal)
                ? host.EndsWith(a[1..], StringComparison.OrdinalIgnoreCase)
                : host.Equals(a, StringComparison.OrdinalIgnoreCase)) && !(_opt.AllowInsecureForTesting && host == _api.Host))
            throw new GitHubException("download", $"Host '{host}' is not on the allow-list.");
    }
}
