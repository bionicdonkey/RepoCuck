namespace RepoCuck.Application;

public sealed class SecurityOptions
{
    public string PublicScheme { get; set; } = "https";
    public string TrustedProxies { get; set; } = "";
    public string ClientIpHeader { get; set; } = "X-Forwarded-For";
    public int HstsMaxAgeDays { get; set; } = 365;
    public string TrustedHosts { get; set; } = "";
    public bool AssumeTlsFront { get; set; }
    public bool IsHttps => PublicScheme.Equals("https", StringComparison.OrdinalIgnoreCase);
}

public sealed class AuthOptions
{
    public bool LocalEnabled { get; set; } = true;
    public string RegistrationMode { get; set; } = "closed";
    public int SessionIdleMinutes { get; set; } = 60;
    public int SessionAbsoluteHours { get; set; } = 12;
    public int MaxFailedAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 15;
}

public sealed class LimitsOptions
{
    public int PendingRequestsPerUser { get; set; } = 10;
    public int RequestsPerHour { get; set; } = 20;
    public int AptRequestsPerMinutePerIp { get; set; } = 600;
    public int LoginAttemptsPer5MinutesPerIp { get; set; } = 10;
}

public sealed class RequestsOptions { public int ProposedExpiryDays { get; set; } = 30; }

public sealed class PolicyOptions
{
    public bool AllowEpoch { get; set; }
    public string ReservedNames { get; set; } = "";
}

public sealed class AptOptions
{
    public string PathPrefix { get; set; } = "/apt";
    public string SigningKeyPath { get; set; } = "/data/keys/repo-signing.key";
    public string? SigningKeyPassphraseFile { get; set; }
    public string? SigningKeyPassphrase { get; set; }
    public string? KeyFingerprint { get; set; }
    public string? PublicHost { get; set; }
    public int InitialBackfillReleases { get; set; } = 20;
    public int ProposedBackfillReleases { get; set; } = 3;
    public string Architectures { get; set; } = "amd64,arm64,armhf,i386,riscv64";
    public bool EnableTesting { get; set; }
}

public sealed class GitHubOptions
{
    public string? Token { get; set; }
    public string ApiBaseUrl { get; set; } = "https://api.github.com";
    public string AssetHostAllowList { get; set; } = "api.github.com,github.com,objects.githubusercontent.com,release-assets.githubusercontent.com,*.githubusercontent.com";
    public long MaxAssetBytes { get; set; } = 2147483648;
    public int RequestTimeoutSeconds { get; set; } = 60;
    public string? WebhookSecret { get; set; }
    /// <summary>Test/dev only: permit http:// and private addresses for the GitHub API and asset hosts.</summary>
    public bool AllowInsecureForTesting { get; set; }
}

public sealed class JobsOptions
{
    public int WorkerConcurrency { get; set; } = 4;
    public int MaxAttempts { get; set; } = 5;
}

public sealed class RetentionOptions
{
    public int VersionsPerPackage { get; set; } = 3;
    public int OrphanGraceDays { get; set; } = 30;
    public int BlobGraceHours { get; set; } = 24;
    public int GenerationCount { get; set; } = 5;
    public int GenerationHours { get; set; } = 48;
}

public sealed class StorageOptions
{
    public string Provider { get; set; } = "filesystem";
    public string Root { get; set; } = "/data";
}

public sealed class BootstrapOptions
{
    public string? AdminUsername { get; set; }
    public string? AdminPasswordFile { get; set; }
}

public sealed class AppOptions
{
    public string Role { get; set; } = "all";
    public string? BaseUrl { get; set; }
    public string Migrate { get; set; } = "apply";
}
