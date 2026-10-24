using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Services;

namespace RepoCuck.Web.Infrastructure;

public static class CurrentUser
{
    public static Guid? Id(this ClaimsPrincipal p) => Guid.TryParse(p.FindFirstValue(ClaimTypes.NameIdentifier), out var g) ? g : null;
    public static bool IsAdmin(this ClaimsPrincipal p) => p.IsInRole(Roles.Admin);
    public static Guid RequireId(this ClaimsPrincipal p) => p.Id() ?? throw new ServiceException("unauthenticated", "Sign in required.", 401);
}

public static class Problems
{
    public static IResult Result(HttpContext ctx, int status, string code, string title, string? detail = null, object? extra = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["type"] = $"https://repocuck.example/errors/{code.Replace('_', '-')}",
            ["title"] = title,
            ["status"] = status,
            ["detail"] = detail,
            ["instance"] = ctx.Request.Path.Value,
            ["code"] = code,
            ["traceId"] = Activity.Current?.Id ?? ctx.TraceIdentifier
        };
        if (extra is not null)
            foreach (var p in extra.GetType().GetProperties()) body[char.ToLowerInvariant(p.Name[0]) + p.Name[1..]] = p.GetValue(extra);
        return Microsoft.AspNetCore.Http.Results.Json(body, statusCode: status, contentType: "application/problem+json");
    }

    public static IResult From(HttpContext ctx, ServiceException e) => Result(ctx, e.Status, e.Code, Title(e.Code), e.Message, e.Extra);

    public static string Title(string code) => code switch
    {
        "validation_error" => "Validation failed",
        "unauthenticated" => "Authentication required",
        "forbidden" => "Forbidden",
        "repository_blocked" => "Repository cannot be requested",
        "not_found" => "Not found",
        "repository_not_found" => "Repository not found",
        "already_watched" => "Repository is already watched",
        "request_pending" => "Request already pending",
        "already_enabled" => "Architectures already enabled",
        "invalid_state" => "Invalid state",
        "request_limit" => "Request limit reached",
        "rate_limited" => "Too many requests",
        "upstream_unavailable" => "Upstream unavailable",
        _ => "Error"
    };

    public static void Configure(IApplicationBuilder app) => app.Run(async ctx =>
    {
        var ex = ctx.Features.Get<IExceptionHandlerFeature>()?.Error;
        var log = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RepoCuck.Errors");
        IResult result;
        if (ex is ServiceException se) result = From(ctx, se);
        else if (ex is BadHttpRequestException bad) result = Result(ctx, 400, "validation_error", "Validation failed", bad.Message.Length < 200 ? "Malformed request." : null);
        else
        {
            log.LogError(ex, "Unhandled exception for {Path}", ctx.Request.Path);
            result = Result(ctx, 500, "internal_error", "Internal error", "An unexpected error occurred. Quote the trace id when reporting it.");
        }
        if (ctx.Response.HasStarted) return;
        ctx.Response.Clear();
        await result.ExecuteAsync(ctx);
    });
}

/// <summary>Honours the configured client-IP header only when the immediate peer is a trusted proxy.</summary>
public sealed class ClientIp(IOptions<SecurityOptions> opt)
{
    private readonly List<System.Net.IPNetwork> _trusted = Parse(opt.Value.TrustedProxies);
    public IReadOnlyList<System.Net.IPNetwork> Trusted => _trusted;

    public static List<System.Net.IPNetwork> Parse(string csv) =>
        csv.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
           .Select(s => System.Net.IPNetwork.Parse(s.Contains('/') ? s : s + (s.Contains(':') ? "/128" : "/32"))).ToList();

    public bool IsTrusted(IPAddress? ip) => ip is not null && _trusted.Any(n => n.Contains(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip));
}

public static class HttpExtensions
{
    public static string ClientAddress(this HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    public static string Nonce(this HttpContext ctx) => (string)(ctx.Items["csp-nonce"] ??= Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)));
}

public sealed class SecurityMiddleware(RequestDelegate next, IOptions<SecurityOptions> opt)
{
    private readonly SecurityOptions _o = opt.Value;

    public async Task Invoke(HttpContext ctx)
    {
        var path = ctx.Request.Path;
        var exempt = path.StartsWithSegments("/healthz") || path.StartsWithSegments("/readyz");
        if (_o.IsHttps && !ctx.Request.IsHttps && !exempt)
        {
            if (HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method))
            {
                ctx.Response.StatusCode = StatusCodes.Status301MovedPermanently;
                ctx.Response.Headers.Location = $"https://{ctx.Request.Host}{ctx.Request.PathBase}{ctx.Request.Path}{ctx.Request.QueryString}";
            }
            else
            {
                ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
                await ctx.Response.WriteAsync("HTTPS required.");
            }
            return;
        }

        var nonce = ctx.Nonce();
        ctx.Response.OnStarting(() =>
        {
            var h = ctx.Response.Headers;
            h["X-Content-Type-Options"] = "nosniff";
            h["Referrer-Policy"] = "no-referrer";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Cross-Origin-Resource-Policy"] = "same-origin";
            h["X-Request-Id"] = Activity.Current?.TraceId.ToString() ?? ctx.TraceIdentifier;
            if (_o.IsHttps && ctx.Request.IsHttps && _o.HstsMaxAgeDays > 0) h["Strict-Transport-Security"] = $"max-age={_o.HstsMaxAgeDays * 86400}";
            var ct = ctx.Response.ContentType;
            if (ct is not null && ct.StartsWith("text/html", StringComparison.OrdinalIgnoreCase))
            {
                h["Content-Security-Policy"] = $"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; img-src 'self' data:; " +
                                               "connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
                h["X-Frame-Options"] = "DENY";
            }
            h.Remove("Server");
            return Task.CompletedTask;
        });
        await next(ctx);
    }
}

/// <summary>CSRF for JSON API mutations: Origin / Sec-Fetch-Site check plus antiforgery header token.</summary>
public sealed class ApiCsrfMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-Repocuck-CSRF";

    public async Task Invoke(HttpContext ctx)
    {
        var m = ctx.Request.Method;
        if (ctx.Request.Path.StartsWithSegments("/api") && !(HttpMethods.IsGet(m) || HttpMethods.IsHead(m) || HttpMethods.IsOptions(m)))
        {
            var fetchSite = ctx.Request.Headers["Sec-Fetch-Site"].ToString();
            if (fetchSite is { Length: > 0 } && fetchSite is not ("same-origin" or "none"))
            { await Deny(ctx); return; }
            var origin = ctx.Request.Headers.Origin.ToString();
            if (origin.Length > 0)
            {
                if (!Uri.TryCreate(origin, UriKind.Absolute, out var o) || !string.Equals(o.Authority, ctx.Request.Host.Value, StringComparison.OrdinalIgnoreCase))
                { await Deny(ctx); return; }
            }
            var af = ctx.RequestServices.GetRequiredService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>();
            try { await af.ValidateRequestAsync(ctx); }
            catch (Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException) { await Deny(ctx); return; }
        }
        await next(ctx);
    }

    private static Task Deny(HttpContext ctx) =>
        Problems.Result(ctx, 403, "forbidden", "Forbidden", "Cross-site request rejected or CSRF token missing.").ExecuteAsync(ctx);
}
