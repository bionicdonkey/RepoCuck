using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Auth;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;
using RepoCuck.Web.Infrastructure;

namespace RepoCuck.Web.Api;

public sealed record ProviderBody(string? Slug, string? DisplayName, string? Authority, string? ClientId, string? ClientSecret, string? ClientSecretFile,
    string? Scopes, string? GroupClaim, string? UsernameClaim, string? EmailClaim, bool? AutoProvision, bool? RequireVerifiedEmail, bool? Enabled);
public sealed record MappingItem(string ClaimValue, string Role, int Priority);
public sealed record PreviewBody(string[]? Groups, MappingItem[]? Mappings);

public static partial class ProviderApi
{
    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,30}$")] private static partial Regex SlugRx();

    public static object Dto(IdentityProvider p) => new
    {
        p.Id,
        p.Slug,
        p.DisplayName,
        p.Authority,
        p.ClientId,
        hasSecret = p.ClientSecretEnc is not null || !string.IsNullOrEmpty(p.ClientSecretFile),
        p.ClientSecretFile,
        p.Scopes,
        p.GroupClaim,
        p.UsernameClaim,
        p.EmailClaim,
        p.AutoProvision,
        p.RequireVerifiedEmail,
        p.Enabled
    };

    public static void MapProviderApi(this RouteGroupBuilder admin)
    {
        var g = admin.MapGroup("/providers");
        g.MapGet("", async (IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            return Results.Json(new { items = (await db.IdentityProviders.AsNoTracking().OrderBy(p => p.Slug).ToListAsync(ct)).Select(Dto) });
        });
        g.MapPost("", async (HttpContext ctx, ProviderBody b, IDbContextFactory<AppDbContext> dbf, OidcSchemeManager mgr, IAuditService audit, IOptions<AuthOptions> auth, CancellationToken ct) =>
        {
            if (b.Slug is null || !SlugRx().IsMatch(b.Slug)) throw new ServiceException("validation_error", "Slug must match ^[a-z0-9][a-z0-9-]{1,30}$.");
            Validate(b, auth.Value, requireAll: true);
            await using var db = await dbf.CreateDbContextAsync(ct);
            if (await db.IdentityProviders.AnyAsync(p => p.Slug == b.Slug, ct)) throw new ServiceException("conflict", "A provider with that slug already exists.", 409);
            var p = new IdentityProvider { Id = Ids.New(), Slug = b.Slug, CreatedAt = DateTimeOffset.UtcNow };
            Apply(p, b, mgr);
            db.IdentityProviders.Add(p);
            await db.SaveChangesAsync(ct);
            await mgr.RefreshAsync(ct);
            await audit.WriteAsync("provider.created", ctx.User.Id(), "provider", p.Id.ToString(), metadata: new { p.Slug }, ct: ct);
            return Results.Json(Dto(p), statusCode: 201);
        });
        g.MapPatch("/{id:guid}", async (HttpContext ctx, Guid id, ProviderBody b, IDbContextFactory<AppDbContext> dbf, OidcSchemeManager mgr, IAuditService audit, IOptions<AuthOptions> auth, CancellationToken ct) =>
        {
            Validate(b, auth.Value, requireAll: false);
            await using var db = await dbf.CreateDbContextAsync(ct);
            var p = await db.IdentityProviders.FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new ServiceException("not_found", "Provider not found.", 404);
            if (b.Enabled == false) await GuardLocalLogin(db, auth.Value, p.Id, ct);
            Apply(p, b, mgr);
            await db.SaveChangesAsync(ct);
            await mgr.RefreshAsync(ct);
            await audit.WriteAsync("provider.updated", ctx.User.Id(), "provider", id.ToString(), ct: ct);
            return Results.Json(Dto(p));
        });
        g.MapDelete("/{id:guid}", async (HttpContext ctx, Guid id, IDbContextFactory<AppDbContext> dbf, OidcSchemeManager mgr, IAuditService audit, IOptions<AuthOptions> auth, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var p = await db.IdentityProviders.FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new ServiceException("not_found", "Provider not found.", 404);
            await GuardLocalLogin(db, auth.Value, p.Id, ct);
            db.IdentityProviders.Remove(p);
            await db.SaveChangesAsync(ct);
            await mgr.RefreshAsync(ct);
            await audit.WriteAsync("provider.deleted", ctx.User.Id(), "provider", id.ToString(), metadata: new { p.Slug }, ct: ct);
            return Results.NoContent();
        });
        g.MapPost("/{id:guid}/test", async (Guid id, IDbContextFactory<AppDbContext> dbf, IHttpClientFactory http, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var p = await db.IdentityProviders.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new ServiceException("not_found", "Provider not found.", 404);
            return Results.Json(await TestAsync(p, http.CreateClient(), ct));
        });
        g.MapGet("/{id:guid}/mappings", async (Guid id, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            return Results.Json(new
            {
                items = await db.RoleMappings.AsNoTracking().Where(m => m.ProviderId == id).OrderByDescending(m => m.Priority).ThenBy(m => m.ClaimValue)
                .Select(m => new MappingItem(m.ClaimValue, m.Role, m.Priority)).ToListAsync(ct)
            });
        });
        g.MapPut("/{id:guid}/mappings", async (HttpContext ctx, Guid id, MappingItem[] items, IDbContextFactory<AppDbContext> dbf, IAuditService audit, CancellationToken ct) =>
        {
            if (items.Any(i => string.IsNullOrWhiteSpace(i.ClaimValue) || !Roles.IsValid(i.Role))) throw new ServiceException("validation_error", "Each mapping needs a claim value and a role of admin or member.");
            if (items.GroupBy(i => i.ClaimValue).Any(x => x.Count() > 1)) throw new ServiceException("validation_error", "Duplicate claim values.");
            await using var db = await dbf.CreateDbContextAsync(ct);
            if (!await db.IdentityProviders.AnyAsync(p => p.Id == id, ct)) throw new ServiceException("not_found", "Provider not found.", 404);
            await db.RoleMappings.Where(m => m.ProviderId == id).ExecuteDeleteAsync(ct);
            foreach (var i in items) db.RoleMappings.Add(new RoleMapping { Id = Ids.New(), ProviderId = id, ClaimValue = i.ClaimValue.Trim(), Role = i.Role, Priority = i.Priority });
            await db.SaveChangesAsync(ct);
            await audit.WriteAsync("provider.mappings_replaced", ctx.User.Id(), "provider", id.ToString(), metadata: new { count = items.Length }, ct: ct);
            return Results.NoContent();
        });
        g.MapPost("/{id:guid}/preview", async (Guid id, PreviewBody b, IDbContextFactory<AppDbContext> dbf, CancellationToken ct) =>
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var maps = b.Mappings is { } m
                ? m.Select(x => new RoleMapping { ClaimValue = x.ClaimValue, Role = x.Role, Priority = x.Priority }).ToList()
                : await db.RoleMappings.AsNoTracking().Where(x => x.ProviderId == id).ToListAsync(ct);
            return Results.Json(new { role = ExternalLoginService.ResolveRole(maps, b.Groups ?? []) });
        });
    }

    private static void Validate(ProviderBody b, AuthOptions auth, bool requireAll)
    {
        if (requireAll && (string.IsNullOrWhiteSpace(b.Authority) || string.IsNullOrWhiteSpace(b.ClientId) || string.IsNullOrWhiteSpace(b.DisplayName)))
            throw new ServiceException("validation_error", "displayName, authority and clientId are required.");
        if (b.Authority is not null)
        {
            if (!Uri.TryCreate(b.Authority, UriKind.Absolute, out var u) || !(u.Scheme == "https" || (u.Scheme == "http" && auth.AllowInsecureOidc)))
                throw new ServiceException("validation_error", "authority must be an https URL.");
            if (!string.IsNullOrEmpty(u.UserInfo)) throw new ServiceException("validation_error", "authority must not contain credentials.");
        }
        if (b.Scopes is not null && !b.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("openid")) throw new ServiceException("validation_error", "scopes must include openid.");
    }

    private static void Apply(IdentityProvider p, ProviderBody b, OidcSchemeManager mgr)
    {
        if (b.DisplayName is { Length: > 0 }) p.DisplayName = b.DisplayName.Trim();
        if (b.Authority is { Length: > 0 }) p.Authority = b.Authority.Trim().TrimEnd('/');
        if (b.ClientId is { Length: > 0 }) p.ClientId = b.ClientId.Trim();
        if (b.ClientSecret is { Length: > 0 }) { p.ClientSecretEnc = mgr.ProtectSecret(b.ClientSecret); p.ClientSecretFile = null; }
        else if (b.ClientSecretFile is not null) { p.ClientSecretFile = b.ClientSecretFile.Length == 0 ? null : b.ClientSecretFile; if (p.ClientSecretFile is not null) p.ClientSecretEnc = null; }
        if (b.Scopes is { Length: > 0 }) p.Scopes = b.Scopes.Trim();
        if (b.GroupClaim is { Length: > 0 }) p.GroupClaim = b.GroupClaim.Trim();
        if (b.UsernameClaim is { Length: > 0 }) p.UsernameClaim = b.UsernameClaim.Trim();
        if (b.EmailClaim is { Length: > 0 }) p.EmailClaim = b.EmailClaim.Trim();
        if (b.AutoProvision is { } ap) p.AutoProvision = ap;
        if (b.RequireVerifiedEmail is { } rv) p.RequireVerifiedEmail = rv;
        if (b.Enabled is { } en) p.Enabled = en;
    }

    /// <summary>FR-AUTH-6: never remove the last way for an admin to sign in.</summary>
    private static async Task GuardLocalLogin(AppDbContext db, AuthOptions auth, Guid providerId, CancellationToken ct)
    {
        if (auth.LocalEnabled) return;
        var otherAdmin = await (from u in db.Users
                                where u.Role == Roles.Admin && u.IsActive && (u.PasswordHash != null && auth.LocalEnabled
                                      || db.ExternalIdentities.Any(e => e.UserId == u.Id && e.ProviderId != providerId))
                                select u.Id).AnyAsync(ct);
        if (!otherAdmin) throw new ServiceException("invalid_state", "Local login is disabled and this is the only way for an admin to sign in.", 409);
    }

    public static async Task<object> TestAsync(IdentityProvider p, HttpClient http, CancellationToken ct)
    {
        try
        {
            http.Timeout = TimeSpan.FromSeconds(15);
            var disco = p.Authority.TrimEnd('/') + "/.well-known/openid-configuration";
            using var doc = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync(disco, ct));
            var root = doc.RootElement;
            var issuer = root.GetProperty("issuer").GetString();
            var jwks = root.GetProperty("jwks_uri").GetString()!;
            using var keys = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync(jwks, ct));
            var count = keys.RootElement.GetProperty("keys").GetArrayLength();
            var endSession = root.TryGetProperty("end_session_endpoint", out var es) ? es.GetString() : null;
            var pkce = root.TryGetProperty("code_challenge_methods_supported", out var cm) && cm.EnumerateArray().Any(x => x.GetString() == "S256");
            var warnings = new List<string>();
            if (!string.Equals(issuer?.TrimEnd('/'), p.Authority.TrimEnd('/'), StringComparison.Ordinal)) warnings.Add("Issuer in discovery differs from the configured authority.");
            if (count == 0) warnings.Add("The JWKS contains no keys.");
            if (!pkce) warnings.Add("Provider does not advertise PKCE S256 support.");
            return new { ok = warnings.Count == 0 || count > 0, issuer, jwksKeys = count, endSession = endSession is not null, authorization = root.GetProperty("authorization_endpoint").GetString(), warnings };
        }
        catch (Exception e) { return new { ok = false, error = e is HttpRequestException ? "Could not reach the provider." : e.Message.Length < 200 ? e.Message : "Discovery failed." }; }
    }
}
