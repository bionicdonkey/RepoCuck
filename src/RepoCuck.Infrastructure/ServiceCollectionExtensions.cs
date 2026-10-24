using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Auth;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.GitHub;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Infrastructure.Signing;
using RepoCuck.Infrastructure.Storage;

namespace RepoCuck.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static AppOptions ReadAppOptions(IConfiguration c) => new()
    {
        Role = c["REPOCUCK:ROLE"] ?? "all",
        BaseUrl = c["REPOCUCK:BASE_URL"],
        Migrate = c["REPOCUCK:MIGRATE"] ?? "apply"
    };

    public static IServiceCollection AddRepoCuck(this IServiceCollection s, IConfiguration c)
    {
        var conn = c.GetConnectionString("Postgres") ?? throw new InvalidOperationException("ConnectionStrings:Postgres is required.");
        s.AddSingleton(NpgsqlDataSource.Create(conn));
        s.AddDbContextFactory<AppDbContext>((sp, o) =>
            o.UseNpgsql(sp.GetRequiredService<NpgsqlDataSource>()).UseSnakeCaseNamingConvention());

        s.Configure<SecurityOptions>(c.GetSection("Security"));
        s.Configure<AuthOptions>(c.GetSection("Auth"));
        s.Configure<LimitsOptions>(c.GetSection("Limits"));
        s.Configure<RequestsOptions>(c.GetSection("Requests"));
        s.Configure<PolicyOptions>(c.GetSection("Policy"));
        s.Configure<AptOptions>(c.GetSection("Apt"));
        s.Configure<GitHubOptions>(c.GetSection("GitHub"));
        s.Configure<JobsOptions>(c.GetSection("Jobs"));
        s.Configure<RetentionOptions>(c.GetSection("Retention"));
        s.Configure<StorageOptions>(c.GetSection("Storage"));
        s.Configure<BootstrapOptions>(c.GetSection("Bootstrap"));
        s.AddSingleton(Options.Create(ReadAppOptions(c)));

        s.AddSingleton<IClock, SystemClock>();
        s.AddSingleton<IBlobStore, FileBlobStore>();
        s.AddSingleton<ISigner, GpgSigner>();
        s.AddHttpClient(GitHubClient.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp => GitHubClient.CreateHandler(sp.GetRequiredService<IOptions<GitHubOptions>>().Value))
            .ConfigureHttpClient((sp, h) => h.Timeout = TimeSpan.FromMinutes(30));
        s.AddSingleton<IGitHubClient, GitHubClient>();

        s.AddSingleton<IAuditService, AuditService>();
        s.AddSingleton<SettingsService>();
        s.AddSingleton<JobQueue>();
        s.AddSingleton<LoginThrottle>();
        s.AddSingleton<SetupTokenService>();
        s.AddScoped<ArbitrationService>();
        s.AddScoped<SyncService>();
        s.AddScoped<PublisherService>();
        s.AddScoped<RetentionService>();
        s.AddScoped<RequestService>();
        s.AddScoped<RepositoryAdminService>();
        s.AddScoped<UserService>();
        s.AddHostedService<Bootstrapper>();
        return s;
    }

    public static IServiceCollection AddRepoCuckWorkers(this IServiceCollection s)
    {
        s.AddHostedService<JobRunner>();
        s.AddHostedService<SchedulerService>();
        return s;
    }
}

public sealed class SetupTokenService
{
    private string? _hash;
    private DateTimeOffset _expires;

    public string Issue()
    {
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24));
        _hash = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
        _expires = DateTimeOffset.UtcNow.AddMinutes(30);
        return token;
    }

    public bool IsActive => _hash is not null && DateTimeOffset.UtcNow < _expires;

    public bool Consume(string? token)
    {
        if (!IsActive || string.IsNullOrEmpty(token)) return false;
        var h = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));
        if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(h), System.Text.Encoding.ASCII.GetBytes(_hash!))) return false;
        _hash = null;
        return true;
    }
}

/// <summary>Runs migrations, seeds suites/settings, verifies the signing key and bootstraps the first admin (spec §12.4).</summary>
public sealed class Bootstrapper(
    NpgsqlDataSource ds, IDbContextFactory<AppDbContext> dbf, IServiceProvider sp, ISigner signer, SetupTokenService setup,
    IOptions<AppOptions> app, IOptions<AptOptions> apt, IOptions<BootstrapOptions> boot, ILogger<Bootstrapper> log) : IHostedLifecycleService
{
    public async Task StartingAsync(CancellationToken ct)
    {
        if (app.Value.Migrate == "apply")
        {
            for (var attempt = 0; ; attempt++)
            {
                try { await MigrationRunner.ApplyAsync(ds, log, ct); break; }
                catch (Exception e) when (attempt < 30 && e is NpgsqlException or System.Net.Sockets.SocketException or TimeoutException)
                {
                    log.LogWarning("Database not ready ({Message}); retrying", e.Message);
                    await Task.Delay(2000, ct);
                }
            }
        }
        await using var db = await dbf.CreateDbContextAsync(ct);
        if (!await db.AptSuites.AnyAsync(ct))
        {
            db.AptSuites.Add(new AptSuite { Id = Guid.CreateVersion7(), Name = "stable", IncludePrereleases = false, IsEnabled = true });
            db.AptSuites.Add(new AptSuite { Id = Guid.CreateVersion7(), Name = "testing", IncludePrereleases = true, NotAutomatic = true, IsEnabled = apt.Value.EnableTesting });
            await db.SaveChangesAsync(ct);
        }
        else
        {
            var testing = await db.AptSuites.FirstOrDefaultAsync(x => x.Name == "testing", ct);
            if (testing is not null && testing.IsEnabled != apt.Value.EnableTesting) { testing.IsEnabled = apt.Value.EnableTesting; await db.SaveChangesAsync(ct); }
        }
        if (app.Value.Role != "web")
        {
            await signer.EnsureReadyAsync(ct);
        }
        if (!await db.Users.AnyAsync(ct))
        {
            var b = boot.Value;
            if (!string.IsNullOrEmpty(b.AdminUsername) && !string.IsNullOrEmpty(b.AdminPasswordFile) && File.Exists(b.AdminPasswordFile))
            {
                var pw = (await File.ReadAllTextAsync(b.AdminPasswordFile, ct)).TrimEnd('\r', '\n');
                using var scope = sp.CreateScope();
                await scope.ServiceProvider.GetRequiredService<UserService>().CreateAsync(b.AdminUsername, b.AdminUsername, null, pw, Roles.Admin, true, null, ct);
                log.LogInformation("Created bootstrap admin '{User}' (password change required at first login).", b.AdminUsername);
            }
            else
            {
                var token = setup.Issue();
                // The token goes to stdout only (not structured logs) and expires after 30 minutes.
                Console.Out.WriteLine($"RepoCuck first-run setup token (valid 30 minutes): {token}");
                Console.Out.WriteLine("Open /setup in a browser and enter this token to create the first admin.");
            }
        }
    }

    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;
    public Task StartedAsync(CancellationToken ct) => Task.CompletedTask;
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
    public Task StoppedAsync(CancellationToken ct) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken ct) => Task.CompletedTask;
}
