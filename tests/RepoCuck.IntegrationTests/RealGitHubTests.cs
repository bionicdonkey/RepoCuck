using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Debian;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.GitHub;
using Xunit.Abstractions;

namespace RepoCuck.Tests;

/// <summary>Opt-in smoke test against the real api.github.com: <c>RC_NETWORK_TESTS=1 dotnet test --filter RealGitHubTests</c>.</summary>
[Collection("pg")]
public class RealGitHubTests(PostgresFixture pg, ITestOutputHelper output)
{
    [Theory]
    [InlineData("BurntSushi", "ripgrep")]
    [InlineData("sharkdp", "fd")]
    [InlineData("sharkdp", "bat")]
    [InlineData("cli", "cli")]
    [InlineData("jgm", "pandoc")]
    [InlineData("wagoodman", "dive")]
    public async Task Latest_release_debs_parse_with_the_real_api_and_cdn(string owner, string name)
    {
        if (Environment.GetEnvironmentVariable("RC_NETWORK_TESTS") != "1") return;
        var cs = await pg.CreateDatabaseAsync();
        var ds = NpgsqlDataSource.Create(cs);
        await MigrationRunner.ApplyAsync(ds, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, default);
        var services = new ServiceCollection();
        services.AddLogging(); services.AddSingleton(ds);
        services.AddDbContextFactory<AppDbContext>((sp, o) => o.UseNpgsql(sp.GetRequiredService<NpgsqlDataSource>()).UseSnakeCaseNamingConvention());
        services.Configure<GitHubOptions>(o => o.Token = Environment.GetEnvironmentVariable("GITHUB_TOKEN"));
        services.AddHttpClient(GitHubClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(sp => GitHubClient.CreateHandler(sp.GetRequiredService<IOptions<GitHubOptions>>().Value));
        services.AddSingleton<GitHubClient>();
        using var sp = services.BuildServiceProvider();
        var gh = sp.GetRequiredService<GitHubClient>();

        var repo = await gh.GetRepoAsync(owner, name, default);
        Assert.True(repo.Id > 0);
        var releases = await gh.GetReleasesAsync(owner, name, 3, default);
        Assert.NotEmpty(releases);
        var debs = releases.SelectMany(r => r.Assets).Where(a => a.Name.EndsWith(".deb", StringComparison.OrdinalIgnoreCase)).Take(3).ToList();
        output.WriteLine($"{owner}/{name}: {releases.Count} releases, {debs.Count} deb assets sampled");
        Assert.NotEmpty(debs);
        var tmp = Path.Combine(Path.GetTempPath(), "rc-real-" + Guid.NewGuid().ToString("N"));
        foreach (var a in debs)
        {
            var dl = await gh.DownloadAssetAsync(a, 200_000_000, tmp, default);
            try
            {
                if (a.DigestSha256 is not null) Assert.Equal(a.DigestSha256, dl.Sha256);
                await using var fs = File.OpenRead(dl.TempPath);
                var info = DebInspector.Inspect(fs, 200_000_000);
                output.WriteLine($"  {a.Name}: {info.Control.Package} {info.Control.Version} {info.Control.Architecture} via {info.ControlArchiveName} digest={(a.DigestSha256 is null ? "none" : "verified")}");
                Assert.NotEmpty(info.Control.Package);
            }
            finally { File.Delete(dl.TempPath); }
        }
    }
}
