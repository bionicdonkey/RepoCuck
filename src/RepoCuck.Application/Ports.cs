namespace RepoCuck.Application;

public interface IClock { DateTimeOffset UtcNow { get; } }
public sealed class SystemClock : IClock { public DateTimeOffset UtcNow => DateTimeOffset.UtcNow; }

public sealed record GhRepo(long Id, string Owner, string Name, string FullName, string HtmlUrl, string? Description,
    string? License, string? DefaultBranch, bool Archived, bool Private);

public sealed record GhAsset(long Id, string Name, long Size, string? ContentType, string? DigestSha256, long DownloadCount, string Url);

public sealed record GhRelease(long Id, string Tag, string? Name, string? Body, bool Prerelease, bool Draft,
    DateTimeOffset? PublishedAt, string? HtmlUrl, IReadOnlyList<GhAsset> Assets);

public class GitHubException(string code, string message, TimeSpan? retryAfter = null, bool transient = false) : Exception(message)
{
    public string Code { get; } = code;
    public TimeSpan? RetryAfter { get; } = retryAfter;
    public bool Transient { get; } = transient;
}

public sealed class GitHubRateLimitedException(DateTimeOffset resetAt) : GitHubException("rate_limited", "GitHub rate limit reached.", transient: true)
{
    public DateTimeOffset ResetAt { get; } = resetAt;
}

public sealed record DownloadResult(string TempPath, long Size, string Sha256, string Sha512);

public interface IGitHubClient
{
    /// <summary>Lookup by owner/name. Throws GitHubException("not_found") if missing or not public.</summary>
    Task<GhRepo> GetRepoAsync(string owner, string name, CancellationToken ct);
    Task<GhRepo> GetRepoByIdAsync(long id, CancellationToken ct);
    /// <summary>Newest-first non-draft releases (up to <paramref name="max"/>).</summary>
    Task<IReadOnlyList<GhRelease>> GetReleasesAsync(string owner, string name, int max, CancellationToken ct);
    Task<DownloadResult> DownloadAssetAsync(GhAsset asset, long maxBytes, string tempDir, CancellationToken ct);
    int RateLimitRemainingPercent { get; }
}

public sealed record StoredBlob(string Sha256, string Sha512, long Size, string StorageKey);

public interface IBlobStore
{
    /// <summary>Moves a temp file into the content-addressed store (idempotent).</summary>
    Task<StoredBlob> AdoptFileAsync(string tempPath, string sha256, string sha512, long size, CancellationToken ct);
    Task<StoredBlob> PutAsync(ReadOnlyMemory<byte> data, CancellationToken ct);
    Stream OpenRead(string storageKey);
    bool Exists(string storageKey);
    Task DeleteAsync(string storageKey, CancellationToken ct);
    string TempDirectory { get; }
}

public sealed record SigningResult(byte[] InRelease, byte[] ReleaseGpg);

public interface ISigner
{
    string Fingerprint { get; }
    Task EnsureReadyAsync(CancellationToken ct);
    Task<SigningResult> SignAsync(byte[] release, CancellationToken ct);
    /// <summary>Public key in binary OpenPGP form.</summary>
    Task<byte[]> ExportPublicKeyAsync(CancellationToken ct);
    Task<byte[]> ExportPublicKeyArmoredAsync(CancellationToken ct);
    Task<DateTimeOffset?> GetKeyExpiryAsync(CancellationToken ct);
}
