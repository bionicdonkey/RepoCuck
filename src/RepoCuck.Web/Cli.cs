using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure;
using RepoCuck.Infrastructure.Auth;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;

namespace RepoCuck.Web;

/// <summary>Offline break-glass operations that talk to the database directly: <c>--migrate</c> and <c>admin list|reset|promote|unlock</c>.</summary>
public static class Cli
{
    public static async Task<int> RunAsync(string[] args, IDictionary<string, string?>? overrides = null, TextWriter? output = null)
    {
        var @out = output ?? Console.Out;
        var builder = WebApplication.CreateBuilder([]);
        if (overrides is not null) builder.Configuration.AddInMemoryCollection(overrides);
        var storage = builder.Configuration.GetSection("Storage").Get<StorageOptions>() ?? new StorageOptions();
        builder.Services.AddRepoCuck(builder.Configuration);
        builder.Services.AddDataProtection().SetApplicationName("RepoCuck").PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(storage.Root, "dpkeys")));
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        using var host = builder.Build();     // not started: hosted services (workers, bootstrapper) stay idle
        var sp = host.Services;

        if (args[0] == "--migrate")
        {
            await MigrationRunner.ApplyAsync(sp.GetRequiredService<NpgsqlDataSource>(), sp.GetRequiredService<ILoggerFactory>().CreateLogger("migrate"), default);
            await @out.WriteLineAsync("Migrations applied.");
            return 0;
        }

        var cmd = args.Length > 1 ? args[1] : "";
        string? Opt(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        await using var scope = sp.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        var dbf = sp.GetRequiredService<IDbContextFactory<AppDbContext>>();
        switch (cmd)
        {
            case "list":
                {
                    await using var db = await dbf.CreateDbContextAsync();
                    foreach (var u in await db.Users.AsNoTracking().OrderBy(u => u.Username).ToListAsync())
                        await @out.WriteLineAsync($"{u.Username,-24} {u.Role,-7} {(u.IsActive ? "enabled" : "disabled"),-9} mfa={(u.TotpEnabled ? "on" : "off")} {u.Id}");
                    return 0;
                }
            case "reset" or "promote" or "unlock":
                {
                    var name = Opt("--username");
                    if (name is null) { await Console.Error.WriteLineAsync("--username is required"); return 2; }
                    await using var db = await dbf.CreateDbContextAsync();
                    var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Username == name.ToLowerInvariant());
                    if (user is null) { await Console.Error.WriteLineAsync($"No such user '{name}'."); return 1; }
                    if (cmd == "reset")
                    {
                        var temp = await users.ResetPasswordAsync(user.Id, user.Id, default);
                        await users.UnlockAsync(user.Id, user.Id, default);
                        await users.UpdateAsync(user.Id, user.Id, null, true, null, default);
                        await @out.WriteLineAsync($"Temporary password for {user.Username}: {temp}\nIt must be changed at the next sign-in.");
                    }
                    else if (cmd == "promote") { await users.UpdateAsync(user.Id, user.Id, Roles.Admin, true, null, default); await @out.WriteLineAsync($"{user.Username} is now an admin."); }
                    else { await users.UnlockAsync(user.Id, user.Id, default); await @out.WriteLineAsync("Unlocked."); }
                    return 0;
                }
            default:
                await Console.Error.WriteLineAsync("Usage: --migrate | admin list | admin reset|promote|unlock --username <name>");
                return 2;
        }
    }
}
