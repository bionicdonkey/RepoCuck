using System.Security.Claims;
using RepoCuck.Application;
using RepoCuck.Domain;

namespace RepoCuck.Infrastructure.Auth;

public static class AuthClaims
{
    public const string Scheme = "repocuck";
    public const string StampClaim = "rc:stamp";
    public const string AbsoluteClaim = "rc:abs";
    public const string MustChangeClaim = "rc:mustchange";
    public const string IdpClaim = "rc:idp";

    public static ClaimsPrincipal BuildPrincipal(User user, AuthOptions auth, string? idpSlug = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()), new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Role, user.Role), new(StampClaim, user.SecurityStamp.ToString()),
            new(AbsoluteClaim, DateTimeOffset.UtcNow.AddHours(auth.SessionAbsoluteHours).ToUnixTimeSeconds().ToString()),
            new("display", user.DisplayName)
        };
        if (user.MustChangePassword) claims.Add(new Claim(MustChangeClaim, "1"));
        if (idpSlug is not null) claims.Add(new Claim(IdpClaim, idpSlug));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme, ClaimTypes.Name, ClaimTypes.Role));
    }
}
