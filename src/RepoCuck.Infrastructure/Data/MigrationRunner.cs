using System.Reflection;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace RepoCuck.Infrastructure.Data;

public static class MigrationRunner
{
    public static async Task ApplyAsync(NpgsqlDataSource ds, ILogger logger, CancellationToken ct)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await Exec(conn, "select pg_advisory_lock(hashtext('repocuck:migrate'))", ct);
        try
        {
            await Exec(conn, "create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())", ct);
            var asm = typeof(MigrationRunner).Assembly;
            var names = asm.GetManifestResourceNames().Where(n => n.EndsWith(".sql", StringComparison.Ordinal)).OrderBy(n => n, StringComparer.Ordinal).ToList();
            foreach (var res in names)
            {
                var name = res.Split('.')[^2];
                await using (var chk = new NpgsqlCommand("select 1 from schema_migrations where name=@n", conn))
                {
                    chk.Parameters.AddWithValue("n", name);
                    if (await chk.ExecuteScalarAsync(ct) is not null) continue;
                }
                logger.LogInformation("Applying migration {Name}", name);
                using var sr = new StreamReader(asm.GetManifestResourceStream(res)!);
                var sql = await sr.ReadToEndAsync(ct);
                await using var tx = await conn.BeginTransactionAsync(ct);
                await using (var cmd = new NpgsqlCommand(sql, conn, tx)) await cmd.ExecuteNonQueryAsync(ct);
                await using (var ins = new NpgsqlCommand("insert into schema_migrations(name) values (@n)", conn, tx))
                {
                    ins.Parameters.AddWithValue("n", name);
                    await ins.ExecuteNonQueryAsync(ct);
                }
                await tx.CommitAsync(ct);
            }
        }
        finally
        {
            await Exec(conn, "select pg_advisory_unlock(hashtext('repocuck:migrate'))", CancellationToken.None);
        }
    }

    private static async Task Exec(NpgsqlConnection c, string sql, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
