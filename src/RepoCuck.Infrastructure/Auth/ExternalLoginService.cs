using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;

namespace RepoCuck.Infrastructure.Auth;

public sealed record ExternalLoginResult(User? User, string? Error);
public sealed record ExternalClaims(string Subject, string? Username, string? Email, bool EmailVerified, string[] Groups);

/// <summary>JIT provisioning, role mapping and account linking for OIDC logins (spec §8.2).</summary>
public sealed class ExternalLoginService(IDbContextFactory<AppDbContext> dbf, IClock clock, IAuditService audit)
{
    /// <summary>Highest-privilege mapping match, else member.</summary>
    public static string ResolveRole(IEnumerable<RoleMapping> mappings, IEnumerable<string> groups)
    {
        var set = new HashSet<string>(groups, StringComparer.Ordinal);
        var matched = mappings.Where(m => set.Contains(m.ClaimValue)).ToList();
        if (matched.Count == 0) return Roles.Member;
        return matched.Any(m => m.Role == Roles.Admin) ? Roles.Admin : Roles.Member;
    }

    /// <summary>Extracts group values from a claim set; supports dotted JSON paths and space/comma separated strings.</summary>
    public static string[] ExtractGroups(IEnumerable<(string Type, string Value)> claims, string path)
    {
        var list = claims.ToList();
        var result = new List<string>();
        foreach (var (type, value) in list.Where(c => c.Type == path)) AddValue(result, value);
        if (result.Count == 0 && path.Contains('.'))
        {
            var parts = path.Split('.');
            var root = list.Where(c => c.Type == parts[0]).Select(c => c.Value).FirstOrDefault();
            if (root is not null)
                try
                {
                    var el = JsonDocument.Parse(root).RootElement;
                    foreach (var p in parts.Skip(1)) { if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(p, out var next)) el = next; else { el = default; break; } }
                    if (el.ValueKind == JsonValueKind.Array) foreach (var x in el.EnumerateArray()) AddValue(result, x.ToString());
                    else if (el.ValueKind == JsonValueKind.String) AddValue(result, el.GetString()!);
                }
                catch (JsonException) { /* not JSON */ }
        }
        return result.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static void AddValue(List<string> result, string value)
    {
        var v = value.Trim();
        if (v.StartsWith('[')) { try { foreach (var e in JsonDocument.Parse(v).RootElement.EnumerateArray()) result.Add(e.ToString()); return; } catch (JsonException) { } }
        foreach (var part in v.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)) result.Add(part);
    }

    private static string SanitizeUsername(string? raw, string fallback)
    {
        var s = new string((raw ?? "").ToLowerInvariant().Select(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '.' or '_' or '-' ? c : '-').ToArray()).Trim('-', '.', '_');
        if (s.Length < 3) s = (s + "-user-" + fallback).Trim('-');
        return s.Length > 60 ? s[..60] : s;
    }

    public async Task<ExternalLoginResult> SignInAsync(string slug, ExternalClaims c, IPAddress? ip, string? correlationId, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var provider = await db.IdentityProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Slug == slug && p.Enabled, ct);
        if (provider is null) return new(null, "Identity provider is not available.");
        var mappings = await db.RoleMappings.AsNoTracking().Where(m => m.ProviderId == provider.Id).ToListAsync(ct);
        var role = ResolveRole(mappings, c.Groups);
        var now = clock.UtcNow;

        var ext = await db.ExternalIdentities.FirstOrDefaultAsync(e => e.ProviderId == provider.Id && e.Subject == c.Subject, ct);
        User user;
        if (ext is not null)
        {
            user = await db.Users.FirstAsync(u => u.Id == ext.UserId, ct);
            ext.LastLoginAt = now; ext.Email = c.Email ?? ext.Email; ext.EmailVerified = c.EmailVerified;
        }
        else
        {
            if (!provider.AutoProvision) return new(null, "Your account has not been provisioned. Ask an administrator.");
            if (!string.IsNullOrEmpty(c.Email) && provider.RequireVerifiedEmail && !c.EmailVerified)
                return new(null, "Your email address is not verified at the identity provider.");
            var baseName = SanitizeUsername(c.Username ?? c.Email?.Split('@')[0], c.Subject.Length > 6 ? c.Subject[..6].ToLowerInvariant() : c.Subject.ToLowerInvariant());
            var name = baseName;
            for (var i = 2; await db.Users.AnyAsync(u => u.Username == name, ct); i++) name = $"{baseName}{i}";
            user = new User
            {
                Id = Ids.New(), Username = name, DisplayName = c.Username ?? name, Email = c.Email, Role = role, SecurityStamp = Guid.NewGuid(),
                CreatedAt = now, UpdatedAt = now
            };
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
            ext = new ExternalIdentity { Id = Ids.New(), UserId = user.Id, ProviderId = provider.Id, Subject = c.Subject, Email = c.Email, EmailVerified = c.EmailVerified, CreatedAt = now, LastLoginAt = now };
            db.ExternalIdentities.Add(ext);
            await audit.WriteAsync("user.provisioned", user.Id, "user", user.Id.ToString(), metadata: new { provider = slug, role }, ip: ip, correlationId: correlationId, ct: ct);
        }
        if (!user.IsActive) return new(null, "This account is disabled.");

        // role follows the IdP on every login unless an admin pinned it; never strand the instance without an admin
        if (!user.RoleLocked && user.Role != role)
        {
            var demotingLastAdmin = user.Role == Roles.Admin && role != Roles.Admin &&
                                    !await db.Users.AnyAsync(u => u.Id != user.Id && u.Role == Roles.Admin && u.IsActive, ct);
            if (!demotingLastAdmin)
            {
                await audit.WriteAsync("user.role_changed", user.Id, "user", user.Id.ToString(), metadata: new { from = user.Role, to = role, via = slug }, ip: ip, ct: ct);
                user.Role = role; user.SecurityStamp = Guid.NewGuid();
            }
        }
        user.LastLoginAt = now; user.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("auth.login", user.Id, "user", user.Id.ToString(), "success", new { provider = slug }, ip, correlationId, ct: ct);
        return new(user, null);
    }

    /// <summary>Links an additional provider identity to an already-signed-in user.</summary>
    public async Task<string?> LinkAsync(Guid userId, string slug, ExternalClaims c, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var provider = await db.IdentityProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Slug == slug && p.Enabled, ct);
        if (provider is null) return "Identity provider is not available.";
        var existing = await db.ExternalIdentities.FirstOrDefaultAsync(e => e.ProviderId == provider.Id && e.Subject == c.Subject, ct);
        if (existing is not null) return existing.UserId == userId ? null : "That identity is already linked to another account.";
        if (await db.ExternalIdentities.AnyAsync(e => e.ProviderId == provider.Id && e.UserId == userId, ct)) return "You already linked an identity from this provider.";
        db.ExternalIdentities.Add(new ExternalIdentity { Id = Ids.New(), UserId = userId, ProviderId = provider.Id, Subject = c.Subject, Email = c.Email, EmailVerified = c.EmailVerified, CreatedAt = clock.UtcNow, LastLoginAt = clock.UtcNow });
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.provider_linked", userId, "user", userId.ToString(), metadata: new { provider = slug }, ct: ct);
        return null;
    }

    public async Task UnlinkAsync(Guid userId, string slug, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.AsNoTracking().FirstAsync(u => u.Id == userId, ct);
        var links = await (from e in db.ExternalIdentities join p in db.IdentityProviders on e.ProviderId equals p.Id where e.UserId == userId select new { e, p.Slug }).ToListAsync(ct);
        var target = links.FirstOrDefault(l => l.Slug == slug) ?? throw new ServiceException("not_found", "That provider is not linked.", 404);
        if (user.PasswordHash is null && links.Count == 1) throw new ServiceException("invalid_state", "Cannot unlink your only sign-in method. Set a password first.", 409);
        db.ExternalIdentities.Remove(target.e);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.provider_unlinked", userId, "user", userId.ToString(), metadata: new { provider = slug }, ct: ct);
    }
}
