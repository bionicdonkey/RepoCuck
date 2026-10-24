using System.ComponentModel.DataAnnotations.Schema;
using System.Net;

namespace RepoCuck.Domain;

public static class Roles
{
    public const string Admin = "admin";
    public const string Member = "member";
    public static bool IsValid(string? r) => r is Admin or Member;
}

public static class RepoState
{
    public const string Proposed = "proposed", Active = "active", Paused = "paused",
        Removed = "removed", Rejected = "rejected", Blocked = "blocked";
}

public static class RequestKind { public const string AddRepo = "add_repo", AddArch = "add_arch"; }
public static class RequestStatus
{
    public const string Pending = "pending", Approved = "approved", Rejected = "rejected", Cancelled = "cancelled";
}

public static class VariantState { public const string Active = "active", Quarantined = "quarantined", Tombstoned = "tombstoned"; }
public static class AssetState
{
    public const string Discovered = "discovered", Downloaded = "downloaded", Parsed = "parsed",
        Excluded = "excluded", Failed = "failed", Quarantined = "quarantined";
}
public static class JobKind
{
    public const string SyncRepository = "SyncRepository", PublishSuite = "PublishSuite",
        RetentionSweep = "RetentionSweep", RebuildApt = "RebuildApt", RefreshReleaseDates = "RefreshReleaseDates",
        BackfillReleases = "BackfillReleases";
}
public static class JobState { public const string Pending = "pending", Running = "running", Succeeded = "succeeded", Failed = "failed", Dead = "dead"; }

public class User
{
    public Guid Id { get; set; }
    public string Username { get; set; } = "";
    public string? Email { get; set; }
    public string DisplayName { get; set; } = "";
    public string? PasswordHash { get; set; }
    public string Role { get; set; } = Roles.Member;
    public bool RoleLocked { get; set; }
    public bool IsActive { get; set; } = true;
    public bool MustChangePassword { get; set; }
    public byte[]? TotpSecretEnc { get; set; }
    public bool TotpEnabled { get; set; }
    public long? TotpLastCounter { get; set; }
    public string[] RecoveryCodesHash { get; set; } = [];
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockoutUntil { get; set; }
    public Guid SecurityStamp { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
}

public class IdentityProvider
{
    public Guid Id { get; set; }
    public string Slug { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Authority { get; set; } = "";
    public string ClientId { get; set; } = "";
    public byte[]? ClientSecretEnc { get; set; }
    public string? ClientSecretFile { get; set; }
    public string Scopes { get; set; } = "openid profile email";
    public string GroupClaim { get; set; } = "groups";
    public string UsernameClaim { get; set; } = "preferred_username";
    public string EmailClaim { get; set; } = "email";
    public bool AutoProvision { get; set; } = true;
    public bool RequireVerifiedEmail { get; set; } = true;
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}

public class RoleMapping
{
    public Guid Id { get; set; }
    public Guid ProviderId { get; set; }
    public string ClaimValue { get; set; } = "";
    public string Role { get; set; } = Roles.Member;
    public int Priority { get; set; }
}

public class ExternalIdentity
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid ProviderId { get; set; }
    public string Subject { get; set; } = "";
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
}

public class Repository
{
    public Guid Id { get; set; }
    public long GithubRepoId { get; set; }
    public string Owner { get; set; } = "";
    public string Name { get; set; } = "";
    public string FullName { get; set; } = "";
    public string HtmlUrl { get; set; } = "";
    public string? Description { get; set; }
    public string? Notes { get; set; }
    public string? LicenseSpdx { get; set; }
    public string? DefaultBranch { get; set; }
    public bool IsArchived { get; set; }
    public string State { get; set; } = RepoState.Proposed;
    public string? StateReason { get; set; }
    public string[] Architectures { get; set; } = [];
    public int SourcePriority { get; set; }
    public bool IncludePrereleases { get; set; }
    public int HoldbackHours { get; set; }
    public string AssetIncludeGlob { get; set; } = "*.deb";
    public string? AssetExcludeGlob { get; set; }
    public long? MaxAssetBytes { get; set; }
    public int SyncIntervalMinutes { get; set; } = 30;
    public DateTimeOffset? NextSyncAt { get; set; }
    public string? ConditionalEtag { get; set; }
    public DateTimeOffset? LastSyncedAt { get; set; }
    public string? LastSyncStatus { get; set; }
    public int ConsecutiveFailures { get; set; }
    public Guid? ProposedBy { get; set; }
    public Guid? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAt { get; set; }
    public DateTimeOffset? RemovedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class ChangeRequest
{
    public Guid Id { get; set; }
    public string Kind { get; set; } = RequestKind.AddRepo;
    public Guid RepositoryId { get; set; }
    public Guid RequestedBy { get; set; }
    public string[] Architectures { get; set; } = [];
    public string? Note { get; set; }
    public string Status { get; set; } = RequestStatus.Pending;
    public Guid? DecidedBy { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
    public string? DecisionNote { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class Release
{
    public Guid Id { get; set; }
    public Guid RepositoryId { get; set; }
    public long GithubReleaseId { get; set; }
    public string TagName { get; set; } = "";
    public string? Name { get; set; }
    public string? Body { get; set; }
    public bool IsPrerelease { get; set; }
    public bool IsDraft { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
    public string? HtmlUrl { get; set; }
    public long DownloadCountTotal { get; set; }
    public DateTimeOffset ObservedAt { get; set; }
}

public class ReleaseAsset
{
    public Guid Id { get; set; }
    public Guid ReleaseId { get; set; }
    public long GithubAssetId { get; set; }
    public string Name { get; set; } = "";
    public long SizeBytes { get; set; }
    public string? ContentType { get; set; }
    public string? DigestSha256 { get; set; }
    public long DownloadCount { get; set; }
    public string SourceUrl { get; set; } = "";
    public string State { get; set; } = AssetState.Discovered;
    public string? ExcludedReason { get; set; }
    public string? FailureReason { get; set; }
    public DateTimeOffset ObservedAt { get; set; }
}

public class Blob
{
    public Guid Id { get; set; }
    public string Sha256 { get; set; } = "";
    public string Sha512 { get; set; } = "";
    public long SizeBytes { get; set; }
    public string StorageKey { get; set; } = "";
    public string ContentType { get; set; } = "";
    public bool IsIndex { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastReferencedAt { get; set; }
}

public class Package
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string NameLower { get; set; } = "";
    public DateTimeOffset FirstSeenAt { get; set; }
}

public class PackageVariant
{
    public Guid Id { get; set; }
    public Guid PackageId { get; set; }
    public string Version { get; set; } = "";
    public string Architecture { get; set; } = "";
    public string Channel { get; set; } = "stable";
    [Column(TypeName = "json")] public string Control { get; set; } = "[]";
    public string Description { get; set; } = "";
    public string Filename { get; set; } = "";
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = "";
    public string Sha512 { get; set; } = "";
    public Guid BlobId { get; set; }
    public string State { get; set; } = VariantState.Active;
    public string? QuarantineReason { get; set; }
    public DateTimeOffset? PublishAfter { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
}

public class PackageSource
{
    public Guid Id { get; set; }
    public Guid VariantId { get; set; }
    public Guid AssetId { get; set; }
    public Guid RepositoryId { get; set; }
    public Guid BlobId { get; set; }
    public bool IsWinner { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class PoolFile
{
    public string Component { get; set; } = "main";
    public string Filename { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long SizeBytes { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class AptSuite
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Component { get; set; } = "main";
    public bool IncludePrereleases { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool NotAutomatic { get; set; }
    public string Origin { get; set; } = "RepoCuck";
    public string Label { get; set; } = "RepoCuck";
    public string Description { get; set; } = "RepoCuck curated APT repository";
    public int ValidUntilDays { get; set; } = 7;
    public int RetainGenerations { get; set; } = 5;
    public int RetainHours { get; set; } = 48;
}

public class AptGeneration
{
    public Guid Id { get; set; }
    public Guid SuiteId { get; set; }
    public long GenerationNo { get; set; }
    public string Status { get; set; } = "building";
    public Guid? ReleaseBlobId { get; set; }
    public Guid? InreleaseBlobId { get; set; }
    public Guid? ReleaseGpgBlobId { get; set; }
    public int PackageCount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ActivatedAt { get; set; }
}

public class AptGenerationFile
{
    public Guid GenerationId { get; set; }
    public string Path { get; set; } = "";
    public Guid BlobId { get; set; }
    public string Sha256 { get; set; } = "";
    public long SizeBytes { get; set; }
}

public class AptCurrent
{
    public Guid SuiteId { get; set; }
    public Guid GenerationId { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class Job
{
    public Guid Id { get; set; }
    public string Kind { get; set; } = "";
    [Column(TypeName = "jsonb")] public string Payload { get; set; } = "{}";
    public string? DedupeKey { get; set; }
    public string State { get; set; } = JobState.Pending;
    public int Attempts { get; set; }
    public int MaxAttempts { get; set; } = 5;
    public DateTimeOffset RunAfter { get; set; }
    public string? LockedBy { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
    public string? LastError { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public class SyncRun
{
    public Guid Id { get; set; }
    public Guid RepositoryId { get; set; }
    public string Trigger { get; set; } = "schedule";
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public string Status { get; set; } = "running";
    public int ReleasesSeen { get; set; }
    public int AssetsSeen { get; set; }
    public int AssetsIngested { get; set; }
    public int AssetsExcluded { get; set; }
    public int AssetsFailed { get; set; }
    public int VariantsCreated { get; set; }
    public int ConflictsFound { get; set; }
    public string? ErrorCategory { get; set; }
    public string? Error { get; set; }
}

public class AuditEntry
{
    public long Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public Guid? ActorUserId { get; set; }
    public string? ActorLabel { get; set; }
    public IPAddress? ActorIp { get; set; }
    public string Action { get; set; } = "";
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }
    public string Outcome { get; set; } = "success";
    [Column(TypeName = "jsonb")] public string Metadata { get; set; } = "{}";
    public string? CorrelationId { get; set; }
}

public class GithubCacheEntry
{
    public string CacheKey { get; set; } = "";
    public string? Etag { get; set; }
    [Column(TypeName = "jsonb")] public string? Payload { get; set; }
    public DateTimeOffset FetchedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
}

public class Setting
{
    public string Key { get; set; } = "";
    [Column(TypeName = "jsonb")] public string Value { get; set; } = "null";
    public DateTimeOffset UpdatedAt { get; set; }
    public Guid? UpdatedBy { get; set; }
}
