using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace RepoCuck.Tests;

public sealed class IdpUser
{
    public string Subject { get; set; } = "sub-1";
    public string Username { get; set; } = "jdoe";
    public string? Email { get; set; } = "jdoe@example.com";
    public bool EmailVerified { get; set; } = true;
    public string[] Groups { get; set; } = [];
}

/// <summary>A minimal OpenID Connect provider (authorization code + PKCE, RS256) for integration tests.</summary>
public sealed class MockIdp : IAsyncDisposable
{
    public const string ClientId = "repocuck-test";
    public const string ClientSecret = "s3cret";
    private readonly WebApplication _app;
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly RsaSecurityKey _key;
    private readonly ConcurrentDictionary<string, (string Challenge, string Nonce, IdpUser User, string RedirectUri)> _codes = new();
    public string Issuer { get; private set; } = "";
    public IdpUser User { get; set; } = new();
    public Func<SecurityTokenDescriptor, SecurityTokenDescriptor>? Mutate { get; set; }
    public RSA? SigningOverride { get; set; }
    public List<IQueryCollection> AuthRequests { get; } = new();
    public string? LastChallengeMethod { get; private set; }
    public bool PkceFailure { get; private set; }

    private MockIdp(WebApplication app) { _app = app; _key = new RsaSecurityKey(_rsa) { KeyId = "k1" }; }

    public static async Task<MockIdp> StartAsync()
    {
        var b = WebApplication.CreateSlimBuilder();
        var app = b.Build();
        app.Urls.Add("http://127.0.0.1:0");
        var idp = new MockIdp(app);
        idp.Map(app);
        await app.StartAsync();
        idp.Issuer = app.Urls.First().TrimEnd('/');
        return idp;
    }

    private void Map(WebApplication app)
    {
        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = Issuer, authorization_endpoint = Issuer + "/authorize", token_endpoint = Issuer + "/token", jwks_uri = Issuer + "/jwks",
            end_session_endpoint = Issuer + "/logout", response_types_supported = new[] { "code" }, subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" }, code_challenge_methods_supported = new[] { "S256" },
            grant_types_supported = new[] { "authorization_code" }, token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" }
        }));
        app.MapGet("/jwks", () =>
        {
            var p = _rsa.ExportParameters(false);
            return Results.Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "k1", n = Base64UrlEncoder.Encode(p.Modulus), e = Base64UrlEncoder.Encode(p.Exponent) } } });
        });
        app.MapGet("/authorize", (HttpContext ctx) =>
        {
            var q = ctx.Request.Query;
            AuthRequests.Add(q);
            if (q["client_id"] != ClientId) return Results.BadRequest("bad client");
            LastChallengeMethod = q["code_challenge_method"];
            if (string.IsNullOrEmpty(q["code_challenge"]) || q["response_type"] != "code") return Results.BadRequest("pkce required");
            var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
            _codes[code] = (q["code_challenge"]!, q["nonce"]!, new IdpUser
            { Subject = User.Subject, Username = User.Username, Email = User.Email, EmailVerified = User.EmailVerified, Groups = User.Groups }, q["redirect_uri"]!);
            return Results.Redirect($"{q["redirect_uri"]}?code={code}&state={Uri.EscapeDataString(q["state"]!)}");
        });
        app.MapPost("/token", async (HttpContext ctx) =>
        {
            var f = await ctx.Request.ReadFormAsync();
            var secret = f["client_secret"].ToString();
            if (secret.Length == 0 && ctx.Request.Headers.Authorization.ToString().StartsWith("Basic "))
                secret = Encoding.UTF8.GetString(Convert.FromBase64String(ctx.Request.Headers.Authorization.ToString()[6..])).Split(':', 2)[1];
            if (Uri.UnescapeDataString(secret) != ClientSecret) return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            if (!_codes.TryRemove(f["code"].ToString(), out var c)) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
            var expected = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(f["code_verifier"].ToString())));
            if (expected != c.Challenge) { PkceFailure = true; return Results.Json(new { error = "invalid_grant", error_description = "pkce" }, statusCode: 400); }
            var claims = new Dictionary<string, object>
            {
                ["sub"] = c.User.Subject, ["preferred_username"] = c.User.Username, ["nonce"] = c.Nonce, ["groups"] = c.User.Groups,
                ["email_verified"] = c.User.EmailVerified
            };
            if (c.User.Email is not null) claims["email"] = c.User.Email;
            var desc = new SecurityTokenDescriptor
            {
                Issuer = Issuer, Audience = ClientId, Claims = claims, IssuedAt = DateTime.UtcNow, NotBefore = DateTime.UtcNow.AddSeconds(-5), Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(SigningOverride is null ? _key : new RsaSecurityKey(SigningOverride) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256)
            };
            if (Mutate is not null) desc = Mutate(desc);
            var idToken = new JsonWebTokenHandler().CreateToken(desc);
            return Results.Json(new { access_token = "at", token_type = "Bearer", expires_in = 300, id_token = idToken });
        });
        app.MapGet("/logout", (HttpContext ctx) =>
        {
            LogoutRequests.Add(ctx.Request.Query);
            var back = ctx.Request.Query["post_logout_redirect_uri"].ToString();
            return string.IsNullOrEmpty(back) ? Results.Ok("bye") : Results.Redirect(back);
        });
    }

    public List<IQueryCollection> LogoutRequests { get; } = new();

    public async ValueTask DisposeAsync() { await _app.StopAsync(); await _app.DisposeAsync(); _rsa.Dispose(); }
}
