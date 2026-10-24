using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;

namespace RepoCuck.Infrastructure.Auth;

/// <summary>Registers one OpenID Connect authentication scheme per enabled provider at runtime (no restart needed).</summary>
public sealed class OidcSchemeManager(
    IAuthenticationSchemeProvider schemes, IOptionsMonitorCache<OpenIdConnectOptions> cache,
    IEnumerable<IPostConfigureOptions<OpenIdConnectOptions>> postConfigure, IDbContextFactory<AppDbContext> dbf,
    IDataProtectionProvider dp, IOptions<AuthOptions> authOpt, IOptions<SecurityOptions> secOpt, ILogger<OidcSchemeManager> log)
{
    public const string Prefix = "oidc:";
    public static string SchemeName(string slug) => Prefix + slug;
    private readonly HashSet<string> _registered = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IDataProtector Protector => dp.CreateProtector("RepoCuck.OidcSecret.v1");

    public byte[] ProtectSecret(string secret) => Protector.Protect(System.Text.Encoding.UTF8.GetBytes(secret));

    public async Task RefreshAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            await using var db = await dbf.CreateDbContextAsync(ct);
            var providers = await db.IdentityProviders.AsNoTracking().Where(p => p.Enabled).ToListAsync(ct);
            var wanted = new HashSet<string>();
            foreach (var p in providers)
            {
                try { await RegisterAsync(p); wanted.Add(SchemeName(p.Slug)); }
                catch (Exception e) { log.LogError(e, "Could not register OIDC provider {Slug}", p.Slug); }
            }
            foreach (var stale in _registered.Except(wanted).ToList())
            {
                schemes.RemoveScheme(stale);
                cache.TryRemove(stale);
                _registered.Remove(stale);
            }
        }
        finally { _gate.Release(); }
    }

    private string? ReadSecret(IdentityProvider p)
    {
        if (p.ClientSecretEnc is not null) return System.Text.Encoding.UTF8.GetString(Protector.Unprotect(p.ClientSecretEnc));
        if (!string.IsNullOrEmpty(p.ClientSecretFile) && File.Exists(p.ClientSecretFile)) return File.ReadAllText(p.ClientSecretFile).TrimEnd('\r', '\n');
        return null;
    }

    private async Task RegisterAsync(IdentityProvider p)
    {
        var name = SchemeName(p.Slug);
        var insecure = authOpt.Value.AllowInsecureOidc;
        if (!p.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !insecure)
            throw new InvalidOperationException("OIDC authority must be https.");
        var o = new OpenIdConnectOptions
        {
            Authority = p.Authority.TrimEnd('/'),
            ClientId = p.ClientId,
            ClientSecret = ReadSecret(p),
            ResponseType = OpenIdConnectResponseType.Code,
            ResponseMode = OpenIdConnectResponseMode.Query,
            UsePkce = true,
            RequireHttpsMetadata = !insecure,
            CallbackPath = $"/signin-oidc/{p.Slug}",
            SignedOutCallbackPath = $"/signout-callback-oidc/{p.Slug}",
            SignedOutRedirectUri = "/login",
            SignInScheme = AuthClaims.Scheme,
            SignOutScheme = AuthClaims.Scheme,
            SaveTokens = false,
            GetClaimsFromUserInfoEndpoint = false,
            MapInboundClaims = false,
            AutomaticRefreshInterval = TimeSpan.FromHours(1),
            ProtocolValidator = { RequireNonce = true, RequireState = true },
        };
        // Correlation/nonce cookies default to Secure+SameSite=None, which browsers refuse on plain http (LAN mode).
        var https = secOpt.Value.IsHttps;
        foreach (var cookie in new[] { o.CorrelationCookie, o.NonceCookie })
        {
            cookie.SecurePolicy = https ? CookieSecurePolicy.Always : CookieSecurePolicy.None;
            cookie.SameSite = https ? SameSiteMode.None : SameSiteMode.Lax;
        }
        o.Scope.Clear();
        foreach (var s in p.Scopes.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)) o.Scope.Add(s);
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true, ValidateLifetime = true, ValidateIssuer = true, ValidateAudience = true,
            ClockSkew = TimeSpan.FromMinutes(2), NameClaimType = "preferred_username", RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
                SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
                SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512]
        };
        var slug = p.Slug;
        o.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProvider = ctx =>
            {
                if (ctx.Properties.Items.ContainsKey("rc_link")) { ctx.ProtocolMessage.Prompt = "login"; ctx.ProtocolMessage.MaxAge = "0"; }
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx => HandleValidatedAsync(ctx, slug),
            OnRemoteFailure = ctx =>
            {
                ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RepoCuck.Oidc")
                    .LogWarning(ctx.Failure, "OIDC sign-in via {Slug} failed: {Message}", slug, ctx.Failure?.Message);
                ctx.HandleResponse();
                ctx.Response.Redirect("/login?error=" + Uri.EscapeDataString("Sign-in with the identity provider failed."));
                return Task.CompletedTask;
            },
        };
        foreach (var pc in postConfigure) pc.PostConfigure(name, o);
        cache.TryRemove(name);
        cache.TryAdd(name, o);
        if (await schemes.GetSchemeAsync(name) is null)
            schemes.AddScheme(new AuthenticationScheme(name, p.DisplayName, typeof(OpenIdConnectHandler)));
        _registered.Add(name);
    }

    private static async Task HandleValidatedAsync(TokenValidatedContext ctx, string slug)
    {
        var sp = ctx.HttpContext.RequestServices;
        var dbf = sp.GetRequiredService<IDbContextFactory<AppDbContext>>();
        var svc = sp.GetRequiredService<ExternalLoginService>();
        var authOpt = sp.GetRequiredService<IOptions<AuthOptions>>().Value;
        IdentityProvider provider;
        await using (var db = await dbf.CreateDbContextAsync()) provider = await db.IdentityProviders.AsNoTracking().FirstAsync(p => p.Slug == slug);

        var principal = ctx.Principal!;
        string? Claim(string t) => principal.FindFirst(t)?.Value;
        var aud = principal.FindAll("aud").Select(c => c.Value).ToList();
        if (aud.Count > 1 && Claim("azp") != provider.ClientId) { ctx.Fail("azp mismatch"); return; }
        var sub = Claim("sub");
        if (string.IsNullOrEmpty(sub)) { ctx.Fail("missing sub"); return; }
        var all = principal.Claims.Select(c => (c.Type, c.Value)).ToList();
        var claims = new ExternalClaims(sub, Claim(provider.UsernameClaim) ?? Claim("preferred_username") ?? Claim("name"), Claim(provider.EmailClaim),
            string.Equals(Claim("email_verified"), "true", StringComparison.OrdinalIgnoreCase), ExternalLoginService.ExtractGroups(all, provider.GroupClaim));

        if (ctx.Properties!.Items.TryGetValue("rc_link", out var linkUser) && Guid.TryParse(linkUser, out var uid))
        {
            ctx.HandleResponse();
            // remote callbacks run before the authentication middleware populates HttpContext.User
            var current = (await ctx.HttpContext.AuthenticateAsync(AuthClaims.Scheme)).Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var err = current == uid.ToString() ? await svc.LinkAsync(uid, slug, claims, ctx.HttpContext.RequestAborted) : "Your session changed during linking.";
            ctx.Response.Redirect(err is null ? "/account?linked=1" : "/account?linkError=" + Uri.EscapeDataString(err));
            return;
        }

        var result = await svc.SignInAsync(slug, claims, ctx.HttpContext.Connection.RemoteIpAddress, ctx.HttpContext.TraceIdentifier, ctx.HttpContext.RequestAborted);
        if (result.User is null)
        {
            ctx.HandleResponse();
            ctx.Response.Redirect("/login?error=" + Uri.EscapeDataString(result.Error ?? "Sign-in failed."));
            return;
        }
        sp.GetRequiredService<Microsoft.Extensions.Caching.Memory.IMemoryCache>().Remove("user:" + result.User.Id);
        ctx.Principal = AuthClaims.BuildPrincipal(result.User, authOpt, slug);
        if ((ctx.TokenEndpointResponse?.IdToken ?? ctx.ProtocolMessage.IdToken) is { } idt) ctx.Properties.StoreTokens([new AuthenticationToken { Name = "id_token", Value = idt }]);
    }
}
