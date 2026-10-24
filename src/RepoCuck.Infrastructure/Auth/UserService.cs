using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;
using RepoCuck.Domain;
using RepoCuck.Infrastructure.Data;
using RepoCuck.Infrastructure.Services;

namespace RepoCuck.Infrastructure.Auth;

public sealed record LoginResult(bool Success, User? User, string? Error, bool TotpRequired = false);

/// <summary>Failure counters per (username, ip) with lockout, plus a softer per-account progressive delay.</summary>
public sealed class LoginThrottle(IClock clock, IOptions<AuthOptions> options)
{
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset Until, DateTimeOffset First)> _pair = new();
    private readonly ConcurrentDictionary<string, (int Count, DateTimeOffset Window)> _acct = new();

    public bool IsLocked(string user, string ip) =>
        _pair.TryGetValue(Key(user, ip), out var s) && s.Until > clock.UtcNow;

    public void Failure(string user, string ip)
    {
        var now = clock.UtcNow;
        _pair.AddOrUpdate(Key(user, ip), _ => (1, now, now), (_, s) =>
        {
            var count = now - s.First > TimeSpan.FromMinutes(options.Value.LockoutMinutes) ? 1 : s.Count + 1;
            return (count, count >= options.Value.MaxFailedAttempts ? now.AddMinutes(options.Value.LockoutMinutes) : s.Until, count == 1 ? now : s.First);
        });
        _acct.AddOrUpdate(user.ToLowerInvariant(), _ => (1, now), (_, s) => now - s.Window > TimeSpan.FromMinutes(15) ? (1, now) : (s.Count + 1, s.Window));
    }

    public TimeSpan AccountDelay(string user) =>
        _acct.TryGetValue(user.ToLowerInvariant(), out var s) && clock.UtcNow - s.Window < TimeSpan.FromMinutes(15) && s.Count >= 20
            ? TimeSpan.FromSeconds(Math.Min(10, (s.Count - 19) * 0.5)) : TimeSpan.Zero;

    public void Success(string user, string ip) { _pair.TryRemove(Key(user, ip), out _); _acct.TryRemove(user.ToLowerInvariant(), out _); }
    public void Reset(string user)
    {
        foreach (var k in _pair.Keys.Where(k => k.StartsWith(user.ToLowerInvariant() + "|", StringComparison.Ordinal))) _pair.TryRemove(k, out _);
        _acct.TryRemove(user.ToLowerInvariant(), out _);
    }
    private static string Key(string user, string ip) => user.ToLowerInvariant() + "|" + ip;
}

public sealed class UserService(
    IDbContextFactory<AppDbContext> dbf, IClock clock, IAuditService audit, LoginThrottle throttle,
    IDataProtectionProvider dp, IOptions<AuthOptions> authOpt)
{
    private IDataProtector Protector => dp.CreateProtector("RepoCuck.Totp.v1");
    private byte[] Protect(string secret) => Protector.Protect(System.Text.Encoding.UTF8.GetBytes(secret));
    private string Unprotect(byte[] data) => System.Text.Encoding.UTF8.GetString(Protector.Unprotect(data));
    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "123456789012", "qwertyuiop12", "letmein12345", "administrator", "changeme1234", "password12345",
        "iloveyou1234", "welcome12345", "123123123123", "000000000000", "111111111111", "passwordpassword", "qwerty123456",
        "adminadminadmin", "abcdefghijkl", "1q2w3e4r5t6y", "p@ssw0rd1234", "repocuckrepocuck"
    };

    public static string? ValidatePassword(string? pw, string? username)
    {
        if (string.IsNullOrEmpty(pw) || pw.Length < 12) return "Password must be at least 12 characters.";
        if (pw.Length > 128) return "Password must be at most 128 characters.";
        if (Common.Contains(pw) || (username is not null && pw.Equals(username, StringComparison.OrdinalIgnoreCase))) return "That password is too easy to guess.";
        if (pw.Distinct().Count() < 5) return "Password is too repetitive.";
        return null;
    }

    public static bool ValidUsername(string? u) =>
        u is { Length: >= 3 and <= 64 } && u.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '.' or '_' or '-');

    public async Task<User> CreateAsync(string username, string displayName, string? email, string? password, string role,
        bool mustChange, Guid? actor, CancellationToken ct)
    {
        username = username.Trim().ToLowerInvariant();
        if (!ValidUsername(username)) throw new ServiceException("validation_error", "Username must be 3-64 characters of a-z, 0-9, '.', '_' or '-'.");
        if (!Roles.IsValid(role)) throw new ServiceException("validation_error", "Invalid role.");
        if (password is not null && ValidatePassword(password, username) is { } err) throw new ServiceException("validation_error", err);
        await using var db = await dbf.CreateDbContextAsync(ct);
        if (await db.Users.AnyAsync(u => u.Username == username, ct)) throw new ServiceException("conflict", "Username already exists.", 409);
        var now = clock.UtcNow;
        var user = new User
        {
            Id = Ids.New(),
            Username = username,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
            Email = string.IsNullOrWhiteSpace(email) ? null : email.Trim(),
            PasswordHash = password is null ? null : PasswordHasher.Hash(password),
            Role = role,
            MustChangePassword = mustChange,
            SecurityStamp = Guid.NewGuid(),
            CreatedAt = now,
            UpdatedAt = now
        };
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.created", actor, "user", user.Id.ToString(), metadata: new { user.Username, user.Role }, ct: ct);
        return user;
    }

    public async Task<User?> FindAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);
    }

    public async Task<LoginResult> LoginAsync(string username, string password, string? totpCode, IPAddress? ip, string? correlationId, CancellationToken ct)
    {
        username = (username ?? "").Trim().ToLowerInvariant();
        var ipText = ip?.ToString() ?? "unknown";
        if (!authOpt.Value.LocalEnabled) return new(false, null, "Local login is disabled.");
        if (throttle.IsLocked(username, ipText))
        {
            await audit.WriteAsync("auth.login", null, "user", username, "denied", new { reason = "locked" }, ip, correlationId, ct: ct);
            return new(false, null, "Too many failed attempts. Try again later.");
        }
        if (throttle.AccountDelay(username) is { } d && d > TimeSpan.Zero) await Task.Delay(d, ct);

        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username, ct);
        var ok = PasswordHasher.Verify(password ?? "", user?.PasswordHash);
        if (!ok || user is null || !user.IsActive)
        {
            throttle.Failure(username, ipText);
            if (user is not null) { user.FailedLoginCount++; await db.SaveChangesAsync(ct); }
            await audit.WriteAsync("auth.login", user?.Id, "user", username, "failure", new { reason = "bad_credentials" }, ip, correlationId, ct: ct);
            return new(false, null, "Invalid username or password.");
        }
        if (user.TotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(totpCode)) return new(false, null, "A verification code is required.", TotpRequired: true);
            if (!await VerifySecondFactorAsync(db, user, totpCode.Trim(), ct))
            {
                throttle.Failure(username, ipText);
                await audit.WriteAsync("auth.login", user.Id, "user", username, "failure", new { reason = "bad_totp" }, ip, correlationId, ct: ct);
                return new(false, null, "Invalid verification code.", TotpRequired: true);
            }
        }
        throttle.Success(username, ipText);
        user.FailedLoginCount = 0; user.LastLoginAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("auth.login", user.Id, "user", user.Id.ToString(), "success", null, ip, correlationId, ct: ct);
        return new(true, user, null);
    }

    private async Task<bool> VerifySecondFactorAsync(AppDbContext db, User user, string code, CancellationToken ct)
    {
        if (user.TotpSecretEnc is not null)
        {
            var secret = Unprotect(user.TotpSecretEnc);
            if (Auth.Totp.Verify(secret, code, clock.UtcNow, user.TotpLastCounter) is { } counter)
            {
                user.TotpLastCounter = counter;
                await db.SaveChangesAsync(ct);
                return true;
            }
        }
        // recovery code (single use)
        var norm = code.Replace("-", "").ToUpperInvariant();
        for (var i = 0; i < user.RecoveryCodesHash.Length; i++)
            if (PasswordHasher.Verify(norm, user.RecoveryCodesHash[i]))
            {
                user.RecoveryCodesHash = user.RecoveryCodesHash.Where((_, j) => j != i).ToArray();
                await db.SaveChangesAsync(ct);
                return true;
            }
        return false;
    }

    public async Task ChangePasswordAsync(Guid userId, string? current, string newPassword, bool skipCurrentCheck, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        if (ValidatePassword(newPassword, user.Username) is { } err) throw new ServiceException("validation_error", err);
        if (!skipCurrentCheck && !user.MustChangePassword && !PasswordHasher.Verify(current ?? "", user.PasswordHash))
            throw new ServiceException("validation_error", "Current password is incorrect.");
        user.PasswordHash = PasswordHasher.Hash(newPassword); user.MustChangePassword = false; user.SecurityStamp = Guid.NewGuid(); user.UpdatedAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.password_changed", userId, "user", userId.ToString(), ct: ct);
    }

    public async Task RevokeSessionsAsync(Guid userId, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(s => s.SetProperty(u => u.SecurityStamp, Guid.NewGuid()), ct);
    }

    // ---- TOTP -------------------------------------------------------------------------------
    public async Task<(string Secret, string Uri)> BeginTotpAsync(Guid userId, string password, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        if (!PasswordHasher.Verify(password, user.PasswordHash)) throw new ServiceException("validation_error", "Password is incorrect.");
        var secret = Auth.Totp.NewSecret();
        user.TotpSecretEnc = Protect(secret); user.TotpEnabled = false; user.TotpLastCounter = null;
        await db.SaveChangesAsync(ct);
        return (secret, Auth.Totp.Uri(secret, user.Username, "RepoCuck"));
    }

    public async Task<string[]> ConfirmTotpAsync(Guid userId, string code, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        if (user.TotpSecretEnc is null) throw new ServiceException("invalid_state", "Start enrollment first.", 409);
        var counter = Auth.Totp.Verify(Unprotect(user.TotpSecretEnc), code.Trim(), clock.UtcNow, user.TotpLastCounter)
                      ?? throw new ServiceException("validation_error", "Invalid verification code.");
        user.TotpEnabled = true; user.TotpLastCounter = counter;
        var codes = NewRecoveryCodes();
        user.RecoveryCodesHash = codes.Select(c => PasswordHasher.Hash(c.Replace("-", ""))).ToArray();
        user.SecurityStamp = Guid.NewGuid();
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.totp_enabled", userId, "user", userId.ToString(), ct: ct);
        return codes;
    }

    public async Task DisableTotpAsync(Guid userId, string password, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstAsync(u => u.Id == userId, ct);
        if (!PasswordHasher.Verify(password, user.PasswordHash)) throw new ServiceException("validation_error", "Password is incorrect.");
        user.TotpEnabled = false; user.TotpSecretEnc = null; user.RecoveryCodesHash = []; user.SecurityStamp = Guid.NewGuid();
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.totp_disabled", userId, "user", userId.ToString(), ct: ct);
    }

    private static string[] NewRecoveryCodes() => Enumerable.Range(0, 10).Select(_ =>
    {
        const string alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var s = new string(Enumerable.Range(0, 10).Select(_ => alpha[RandomNumberGenerator.GetInt32(alpha.Length)]).ToArray());
        return s[..5] + "-" + s[5..];
    }).ToArray();

    // ---- admin ops ----------------------------------------------------------------------------
    private static async Task GuardLastAdmin(AppDbContext db, User user, CancellationToken ct)
    {
        if (user.Role != Roles.Admin || !user.IsActive) return;
        var others = await db.Users.CountAsync(u => u.Id != user.Id && u.Role == Roles.Admin && u.IsActive, ct);
        if (others == 0) throw new ServiceException("invalid_state", "The last enabled admin cannot be disabled or demoted.", 409);
    }

    public async Task<User> UpdateAsync(Guid id, Guid actor, string? role, bool? isActive, string? displayName, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable, ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) ?? throw new ServiceException("not_found", "User not found.", 404);
        if (role is not null)
        {
            if (!Roles.IsValid(role)) throw new ServiceException("validation_error", "Invalid role.");
            if (role != Roles.Admin) await GuardLastAdmin(db, user, ct);
            user.Role = role; user.RoleLocked = true; user.SecurityStamp = Guid.NewGuid();
        }
        if (isActive is false)
        {
            await GuardLastAdmin(db, user, ct);
            user.IsActive = false; user.SecurityStamp = Guid.NewGuid();
            await db.ChangeRequests.Where(r => r.RequestedBy == id && r.Status == RequestStatus.Pending)
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, RequestStatus.Cancelled).SetProperty(r => r.DecidedAt, clock.UtcNow).SetProperty(r => r.DecisionNote, "requester disabled"), ct);
        }
        else if (isActive is true) user.IsActive = true;
        if (displayName is { Length: > 0 }) user.DisplayName = displayName.Trim();
        user.UpdatedAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        await audit.WriteAsync("user.updated", actor, "user", id.ToString(), metadata: new { role, isActive }, ct: ct);
        return user;
    }

    public async Task<string> ResetPasswordAsync(Guid id, Guid actor, CancellationToken ct)
    {
        var temp = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', 'x').Replace('/', 'y').TrimEnd('=');
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) ?? throw new ServiceException("not_found", "User not found.", 404);
        user.PasswordHash = PasswordHasher.Hash(temp); user.MustChangePassword = true; user.SecurityStamp = Guid.NewGuid(); user.UpdatedAt = clock.UtcNow;
        await db.SaveChangesAsync(ct);
        throttle.Reset(user.Username);
        await audit.WriteAsync("user.password_reset", actor, "user", id.ToString(), ct: ct);
        return temp;
    }

    public async Task UnlockAsync(Guid id, Guid actor, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) ?? throw new ServiceException("not_found", "User not found.", 404);
        throttle.Reset(user.Username); user.FailedLoginCount = 0; user.LockoutUntil = null;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.unlocked", actor, "user", id.ToString(), ct: ct);
    }

    public async Task ResetMfaAsync(Guid id, Guid actor, CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) ?? throw new ServiceException("not_found", "User not found.", 404);
        user.TotpEnabled = false; user.TotpSecretEnc = null; user.RecoveryCodesHash = []; user.SecurityStamp = Guid.NewGuid();
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync("user.mfa_reset", actor, "user", id.ToString(), ct: ct);
    }

    // ---- bootstrap ---------------------------------------------------------------------------
    public async Task<bool> AnyUsersAsync(CancellationToken ct)
    {
        await using var db = await dbf.CreateDbContextAsync(ct);
        return await db.Users.AnyAsync(ct);
    }
}
