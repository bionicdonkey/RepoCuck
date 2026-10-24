using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Auth;

namespace RepoCuck.Web.Infrastructure;

public static class AuthSetup
{
    public const string Scheme = AuthClaims.Scheme;
    public const string StampClaim = AuthClaims.StampClaim;
    public const string AbsoluteClaim = AuthClaims.AbsoluteClaim;
    public const string MustChangeClaim = AuthClaims.MustChangeClaim;

    public static void AddRepoCuckAuth(this IServiceCollection services, SecurityOptions sec, AuthOptions auth)
    {
        services.AddMemoryCache();
        services.AddAuthentication(Scheme).AddCookie(Scheme, o =>
        {
            o.Cookie.Name = sec.IsHttps ? "__Host-repocuck" : "repocuck";
            o.Cookie.HttpOnly = true;
            o.Cookie.SameSite = SameSiteMode.Lax;
            o.Cookie.Path = "/";
            o.Cookie.SecurePolicy = sec.IsHttps ? CookieSecurePolicy.Always : CookieSecurePolicy.None;
            o.ExpireTimeSpan = TimeSpan.FromMinutes(auth.SessionIdleMinutes);
            o.SlidingExpiration = true;
            o.LoginPath = "/login";
            o.AccessDeniedPath = "/denied";
            o.Events = new CookieAuthenticationEvents
            {
                OnRedirectToLogin = ctx =>
                {
                    if (IsApi(ctx.Request)) { ctx.Response.StatusCode = 401; return Task.CompletedTask; }
                    ctx.Response.Redirect(ctx.RedirectUri);
                    return Task.CompletedTask;
                },
                OnRedirectToAccessDenied = ctx =>
                {
                    if (IsApi(ctx.Request)) { ctx.Response.StatusCode = 403; return Task.CompletedTask; }
                    ctx.Response.Redirect(ctx.RedirectUri);
                    return Task.CompletedTask;
                },
                OnValidatePrincipal = async ctx =>
                {
                    var p = ctx.Principal;
                    var id = p?.Id();
                    var abs = p?.FindFirstValue(AbsoluteClaim);
                    var stamp = p?.FindFirstValue(StampClaim);
                    if (id is null || stamp is null || !long.TryParse(abs, out var absUnix) || DateTimeOffset.FromUnixTimeSeconds(absUnix) < DateTimeOffset.UtcNow)
                    { await Reject(ctx); return; }
                    var cache = ctx.HttpContext.RequestServices.GetRequiredService<IMemoryCache>();
                    var state = await cache.GetOrCreateAsync("user:" + id, async e =>
                    {
                        e.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30);
                        var u = await ctx.HttpContext.RequestServices.GetRequiredService<UserService>().FindAsync(id.Value);
                        return u is null ? null : new UserState(u.SecurityStamp.ToString(), u.IsActive);
                    });
                    if (state is null || !state.Active || state.Stamp != stamp) await Reject(ctx);
                }
            };
        });
        services.AddAuthorization(o =>
        {
            o.FallbackPolicy = null;
            o.AddPolicy("Authenticated", p => p.RequireAuthenticatedUser());
            o.AddPolicy("Admin", p => p.RequireAuthenticatedUser().RequireRole(Roles.Admin));
        });
    }

    private sealed record UserState(string Stamp, bool Active);

    private static async Task Reject(CookieValidatePrincipalContext ctx)
    {
        ctx.RejectPrincipal();
        await ctx.HttpContext.SignOutAsync(Scheme);
    }

    private static bool IsApi(HttpRequest r) => r.Path.StartsWithSegments("/api");

    public static async Task SignInAsync(HttpContext ctx, User user, AuthOptions auth)
    {
        // a fresh session must not be judged against a stale cached stamp
        ctx.RequestServices.GetRequiredService<IMemoryCache>().Remove("user:" + user.Id);
        await ctx.SignInAsync(Scheme, AuthClaims.BuildPrincipal(user, auth), new AuthenticationProperties { IsPersistent = false });
    }
}
