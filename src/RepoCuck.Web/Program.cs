using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using RepoCuck.Application;
using RepoCuck.Infrastructure.Auth;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure;
using RepoCuck.Web.Api;
using RepoCuck.Web.Infrastructure;

if (args.Length > 0 && (args[0] is "--migrate" or "admin")) return await RepoCuck.Web.Cli.RunAsync(args);

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;
builder.WebHost.ConfigureKestrel(k => { k.AddServerHeader = false; k.Limits.MaxRequestHeadersTotalSize = 16 * 1024; k.Limits.MaxRequestLineSize = 8 * 1024; k.Limits.MaxRequestBodySize = 1024 * 1024; });

var sec = cfg.GetSection("Security").Get<SecurityOptions>() ?? new SecurityOptions();
var auth = cfg.GetSection("Auth").Get<AuthOptions>() ?? new AuthOptions();
var appOpt = ServiceCollectionExtensions.ReadAppOptions(cfg);
var storage = cfg.GetSection("Storage").Get<StorageOptions>() ?? new StorageOptions();
var aptOpt = cfg.GetSection("Apt").Get<AptOptions>() ?? new AptOptions();

ValidateConfiguration(builder, sec, appOpt);

// Host header allow-list derived from BASE_URL (plus localhost for health checks).
if (string.IsNullOrEmpty(cfg["AllowedHosts"]) || cfg["AllowedHosts"] == "*")
{
    var hosts = new List<string> { "localhost", "127.0.0.1" };
    if (!string.IsNullOrEmpty(sec.TrustedHosts)) hosts.AddRange(sec.TrustedHosts.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries));
    if (Uri.TryCreate(appOpt.BaseUrl, UriKind.Absolute, out var bu)) hosts.Add(bu.Host);
    if (hosts.Count > 2 || !builder.Environment.IsDevelopment()) cfg["AllowedHosts"] = hosts.Count > 2 ? string.Join(';', hosts.Distinct()) : "*";
}

builder.Services.AddRepoCuck(cfg);
if (appOpt.Role is "all" or "worker") builder.Services.AddRepoCuckWorkers();
builder.Services.AddSingleton<ClientIp>();
builder.Services.AddRepoCuckAuth(sec, auth);
builder.Services.AddDataProtection().SetApplicationName("RepoCuck")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(storage.Root, "dpkeys")));
builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = ApiCsrfMiddleware.HeaderName;
    o.Cookie.Name = sec.IsHttps ? "__Host-repocuck.af" : "repocuck.af";
    o.Cookie.SecurePolicy = sec.IsHttps ? CookieSecurePolicy.Always : CookieSecurePolicy.None;
    o.Cookie.SameSite = SameSiteMode.Lax;
});
builder.Services.AddRazorPages(o =>
{
    o.Conventions.AuthorizeFolder("/", "Authenticated");
    o.Conventions.AuthorizeFolder("/Admin", "Admin");
    o.Conventions.AllowAnonymousToPage("/Login");
    o.Conventions.AllowAnonymousToPage("/Setup");
    o.Conventions.AllowAnonymousToPage("/Denied");
    o.Conventions.AllowAnonymousToPage("/Error");
    o.Conventions.AddPageApplicationModelConvention("/Login", m => m.EndpointMetadata.Add(new Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute("login")));
});
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    var trusted = ClientIp.Parse(sec.TrustedProxies);
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    o.ForwardedForHeaderName = string.IsNullOrWhiteSpace(sec.ClientIpHeader) ? "X-Forwarded-For" : sec.ClientIpHeader;
    o.KnownProxies.Clear();
    o.KnownIPNetworks.Clear();
    foreach (var n in trusted) o.KnownIPNetworks.Add(n);
    o.ForwardLimit = 1;
    o.RequireHeaderSymmetry = false;
});
builder.Services.AddProblemDetails();
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.OnRejected = async (ctx, ct) =>
    {
        ctx.HttpContext.Response.Headers.RetryAfter = "60";
        await Problems.Result(ctx.HttpContext, 429, "rate_limited", "Too many requests", "Rate limit exceeded; retry later.").ExecuteAsync(ctx.HttpContext);
    };
    var loginLimit = cfg.GetSection("Limits").Get<LimitsOptions>()?.LoginAttemptsPer5MinutesPerIp ?? 10;
    o.AddPolicy("login", ctx => HttpMethods.IsPost(ctx.Request.Method)
        ? RateLimitPartition.GetFixedWindowLimiter(ctx.ClientAddress(), _ => new FixedWindowRateLimiterOptions { PermitLimit = loginLimit, Window = TimeSpan.FromMinutes(5) })
        : RateLimitPartition.GetNoLimiter("login-read"));
    o.AddPolicy("api", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.User.Id()?.ToString() ?? ctx.ClientAddress(), _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1) }));
    var aptLimit = cfg.GetSection("Limits").Get<LimitsOptions>()?.AptRequestsPerMinutePerIp ?? 600;
    o.AddPolicy("apt", ctx => RateLimitPartition.GetTokenBucketLimiter(ctx.ClientAddress(), _ => new TokenBucketRateLimiterOptions
    { TokenLimit = Math.Max(100, aptLimit / 6), TokensPerPeriod = Math.Max(1, aptLimit / 6), ReplenishmentPeriod = TimeSpan.FromSeconds(10), QueueLimit = 0 }));
});
builder.Services.AddSingleton<Metrics>();

var app = builder.Build();

if (sec.IsHttps == false) app.Logger.LogWarning("Security:PublicScheme=http: cookies are not Secure and HSTS is disabled. Use only on a trusted network.");

app.UseExceptionHandler(Problems.Configure);
if (ClientIp.Parse(sec.TrustedProxies).Count > 0) app.UseForwardedHeaders();
app.UseMiddleware<SecurityMiddleware>();
app.UseHostFiltering();
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.Use(async (ctx, next) =>
{
    // Accounts flagged must_change_password can only reach the password-change flow.
    if (ctx.User.Identity?.IsAuthenticated == true && ctx.User.HasClaim(AuthSetup.MustChangeClaim, "1"))
    {
        var p = ctx.Request.Path;
        var allowed = p.StartsWithSegments("/account") || p.StartsWithSegments("/auth/logout") || p.StartsWithSegments("/api/v1/me/password")
            || p.StartsWithSegments("/api/v1/csrf") || p.StartsWithSegments("/css") || p.StartsWithSegments("/js") || p.StartsWithSegments("/healthz")
            || p.StartsWithSegments("/readyz") || p.StartsWithSegments("/apt");
        if (!allowed)
        {
            if (p.StartsWithSegments("/api")) await Problems.Result(ctx, 403, "password_change_required", "Password change required", "Change your password to continue.").ExecuteAsync(ctx);
            else ctx.Response.Redirect("/account?mustChange=1");
            return;
        }
    }
    await next();
});
app.UseAuthorization();
app.UseMiddleware<ApiCsrfMiddleware>();

app.MapSystemEndpoints();
app.MapAptEndpoints(aptOpt.PathPrefix);
var api = app.MapGroup("/api/v1").RequireAuthorization("Authenticated").RequireRateLimiting("api");
api.MapCoreApi();
api.MapAdminApi();
app.MapGet("/auth/oidc/{slug}/signin", async (HttpContext ctx, string slug, string? returnUrl, IDbContextFactory<AppDbContext> dbf, IAuthenticationSchemeProvider schemes) =>
{
    await using var db = await dbf.CreateDbContextAsync();
    var name = OidcSchemeManager.SchemeName(slug);
    if (!await db.IdentityProviders.AnyAsync(p => p.Slug == slug && p.Enabled) || await schemes.GetSchemeAsync(name) is null) return Results.NotFound();
    var target = !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") && !returnUrl.StartsWith("/\\") ? returnUrl : "/repos";
    return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [name]);
}).AllowAnonymous().RequireRateLimiting("login");
app.MapRazorPages();
app.MapGet("/", (HttpContext c) => Results.Redirect("/repos")).ExcludeFromDescription();

await app.RunAsync();
return 0;

static void ValidateConfiguration(WebApplicationBuilder b, SecurityOptions sec, AppOptions app)
{
    var prod = b.Environment.IsProduction();
    if (prod && string.IsNullOrEmpty(app.BaseUrl)) throw new InvalidOperationException("REPOCUCK__BASE_URL is required in Production.");
    if (Uri.TryCreate(app.BaseUrl, UriKind.Absolute, out var u) && !u.Scheme.Equals(sec.PublicScheme, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException($"BASE_URL scheme '{u.Scheme}' disagrees with Security:PublicScheme '{sec.PublicScheme}'.");
    if (sec.PublicScheme is not ("https" or "http")) throw new InvalidOperationException("Security:PublicScheme must be https or http.");
    if (prod && sec.IsHttps && string.IsNullOrWhiteSpace(sec.TrustedProxies) && !sec.AssumeTlsFront)
        throw new InvalidOperationException("PublicScheme=https requires Security:TrustedProxies (the TLS front) or Security:AssumeTlsFront=true.");
}

public partial class Program;
