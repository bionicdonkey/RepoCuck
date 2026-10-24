using Microsoft.EntityFrameworkCore;
using RepoCuck.Domain;

namespace RepoCuck.Infrastructure.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<IdentityProvider> IdentityProviders => Set<IdentityProvider>();
    public DbSet<RoleMapping> RoleMappings => Set<RoleMapping>();
    public DbSet<ExternalIdentity> ExternalIdentities => Set<ExternalIdentity>();
    public DbSet<Repository> Repositories => Set<Repository>();
    public DbSet<ChangeRequest> ChangeRequests => Set<ChangeRequest>();
    public DbSet<Release> Releases => Set<Release>();
    public DbSet<ReleaseAsset> ReleaseAssets => Set<ReleaseAsset>();
    public DbSet<Blob> Blobs => Set<Blob>();
    public DbSet<Package> Packages => Set<Package>();
    public DbSet<PackageVariant> PackageVariants => Set<PackageVariant>();
    public DbSet<PackageSource> PackageSources => Set<PackageSource>();
    public DbSet<PoolFile> PoolFiles => Set<PoolFile>();
    public DbSet<AptSuite> AptSuites => Set<AptSuite>();
    public DbSet<AptGeneration> AptGenerations => Set<AptGeneration>();
    public DbSet<AptGenerationFile> AptGenerationFiles => Set<AptGenerationFile>();
    public DbSet<AptCurrent> AptCurrent => Set<AptCurrent>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<SyncRun> SyncRuns => Set<SyncRun>();
    public DbSet<AuditEntry> AuditLog => Set<AuditEntry>();
    public DbSet<GithubCacheEntry> GithubCache => Set<GithubCacheEntry>();
    public DbSet<Setting> Settings => Set<Setting>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.Property(x => x.Username).HasColumnType("citext");
            e.Property(x => x.Email).HasColumnType("citext");
        });
        b.Entity<ExternalIdentity>().Property(x => x.Email).HasColumnType("citext");
        b.Entity<Repository>().Property(x => x.FullName).HasColumnType("citext");
        b.Entity<Package>().Property(x => x.NameLower).HasComputedColumnSql("lower(name)", stored: true);
        b.Entity<PoolFile>().HasKey(x => new { x.Component, x.Filename });
        b.Entity<AptGenerationFile>().HasKey(x => new { x.GenerationId, x.Path });
        b.Entity<AptCurrent>().HasKey(x => x.SuiteId);
        b.Entity<Setting>().HasKey(x => x.Key);
        b.Entity<GithubCacheEntry>().HasKey(x => x.CacheKey);
        b.Entity<AuditEntry>().ToTable("audit_log");
        b.Entity<GithubCacheEntry>().ToTable("github_cache");
        b.Entity<AptCurrent>().ToTable("apt_current");
        b.Entity<Setting>().ToTable("settings");
        b.Entity<Package>().ToTable("packages");

        // Foreign keys (no navigations) so EF orders inserts/deletes correctly; cascade behaviour lives in the SQL schema.
        void Fk<TDep, TPrincipal>(System.Linq.Expressions.Expression<Func<TDep, object?>> fk) where TDep : class where TPrincipal : class =>
            b.Entity<TDep>().HasOne<TPrincipal>().WithMany().HasForeignKey(fk).OnDelete(DeleteBehavior.NoAction);
        Fk<ChangeRequest, Repository>(x => x.RepositoryId);
        Fk<ChangeRequest, User>(x => x.RequestedBy);
        Fk<Release, Repository>(x => x.RepositoryId);
        Fk<ReleaseAsset, Release>(x => x.ReleaseId);
        Fk<PackageVariant, Package>(x => x.PackageId);
        Fk<PackageVariant, Blob>(x => x.BlobId);
        Fk<PackageSource, PackageVariant>(x => x.VariantId);
        Fk<PackageSource, ReleaseAsset>(x => x.AssetId);
        Fk<PackageSource, Repository>(x => x.RepositoryId);
        Fk<PackageSource, Blob>(x => x.BlobId);
        Fk<AptGeneration, AptSuite>(x => x.SuiteId);
        Fk<AptGenerationFile, AptGeneration>(x => x.GenerationId);
        Fk<AptGenerationFile, Blob>(x => x.BlobId);
        Fk<AptCurrent, AptSuite>(x => x.SuiteId);
        Fk<AptCurrent, AptGeneration>(x => x.GenerationId);
        Fk<SyncRun, Repository>(x => x.RepositoryId);
        Fk<RoleMapping, IdentityProvider>(x => x.ProviderId);
        Fk<ExternalIdentity, User>(x => x.UserId);
        Fk<ExternalIdentity, IdentityProvider>(x => x.ProviderId);
    }
}
