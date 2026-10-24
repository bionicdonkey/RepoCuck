using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RepoCuck.Application;

namespace RepoCuck.Infrastructure.Signing;

/// <summary>Signs Release files by shelling out to gpg (no shell; ArgumentList only).</summary>
public sealed class GpgSigner(IOptions<AptOptions> options, IOptions<StorageOptions> storage, ILogger<GpgSigner> logger) : ISigner
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _fingerprint;
    private bool _ready;
    private string GnupgHome => Environment.GetEnvironmentVariable("GNUPGHOME") ?? Path.Combine(storage.Value.Root, "gnupg");

    private List<string> _active = new();
    private string ActiveFile => Path.Combine(GnupgHome, "active-fingerprints");

    public string Fingerprint => _fingerprint ?? throw new InvalidOperationException("Signer not initialised.");
    public IReadOnlyList<string> ActiveFingerprints => _active;

    public async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        await _gate.WaitAsync(ct);
        try
        {
            if (_ready) return;
            var o = options.Value;
            Directory.CreateDirectory(GnupgHome);
            TryChmod(GnupgHome, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (!File.Exists(o.SigningKeyPath))
            {
                if (!File.Exists(Path.Combine(GnupgHome, "keys.generated")) && !HasSecretKey())
                {
                    logger.LogWarning("No signing key at {Path}; generating a new Ed25519 signing key in {Home}.", o.SigningKeyPath, GnupgHome);
                    await GenerateKeyAsync(ct);
                }
            }
            else
            {
                await Run(["--batch", "--no-tty", "--yes", "--import", o.SigningKeyPath], null, ct, passphrase: true);
            }
            _fingerprint = await FindFingerprintAsync(ct);
            _active = LoadActive() ?? [_fingerprint];
            _fingerprint = _active[0];
            if (o.KeyFingerprint is { Length: > 0 } pinned &&
                !string.Equals(pinned.Replace(" ", ""), _fingerprint, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Signing key fingerprint {_fingerprint} does not match pinned {pinned}.");
            // Verify the key is usable by signing a probe.
            await SignAsyncCore("probe\n"u8.ToArray(), detached: true, ct);
            _ready = true;
            logger.LogInformation("Signing key ready: {Fingerprint}", _fingerprint);
        }
        finally { _gate.Release(); }
    }

    private List<string>? LoadActive()
    {
        if (!File.Exists(ActiveFile)) return null;
        var l = File.ReadAllLines(ActiveFile).Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
        return l.Count == 0 ? null : l;
    }

    private async Task SaveActiveAsync(IEnumerable<string> fprs, CancellationToken ct) =>
        await File.WriteAllLinesAsync(ActiveFile, fprs, ct);

    private async Task<List<(string Fpr, DateTimeOffset? Expires)>> ListSecretKeysAsync(CancellationToken ct)
    {
        var (output, _) = await Run(["--batch", "--no-tty", "--list-secret-keys", "--with-colons", "--fingerprint"], null, ct);
        var result = new List<(string, DateTimeOffset?)>();
        DateTimeOffset? exp = null; var expectFpr = false;
        foreach (var line in output.Split('\n'))
        {
            if (line.StartsWith("sec:", StringComparison.Ordinal))
            {
                var f = line.Split(':');
                exp = f.Length > 6 && long.TryParse(f[6], out var e) && e > 0 ? DateTimeOffset.FromUnixTimeSeconds(e) : null;
                expectFpr = true;
            }
            else if (expectFpr && line.StartsWith("fpr:", StringComparison.Ordinal)) { result.Add((line.Split(':')[9], exp)); expectFpr = false; }
        }
        return result;
    }

    public async Task<IReadOnlyList<SigningKeyInfo>> ListKeysAsync(CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        return (await ListSecretKeysAsync(ct)).Select(k => new SigningKeyInfo(k.Fpr, k.Expires, _active.Contains(k.Fpr))).ToList();
    }

    public async Task<string> StartRotationAsync(CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        await _gate.WaitAsync(ct);
        try
        {
            if (_active.Count > 1) throw new InvalidOperationException("A rotation is already in progress.");
            var before = (await ListSecretKeysAsync(ct)).Select(k => k.Fpr).ToHashSet();
            await GenerateKeyAsync(ct);
            var added = (await ListSecretKeysAsync(ct)).Select(k => k.Fpr).Except(before).FirstOrDefault()
                        ?? throw new InvalidOperationException("Key generation did not produce a new key.");
            _active = [_active[0], added];   // sign with both during the overlap window
            await SaveActiveAsync(_active, ct);
            return added;
        }
        finally { _gate.Release(); }
    }

    public async Task CompleteRotationAsync(CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        await _gate.WaitAsync(ct);
        try
        {
            if (_active.Count < 2) throw new InvalidOperationException("No rotation is in progress.");
            var keep = _active[^1];
            foreach (var old in _active.Where(f => f != keep).ToList())
                await Run(["--batch", "--no-tty", "--yes", "--delete-secret-and-public-key", old], null, ct);
            _active = [keep];
            _fingerprint = keep;
            await SaveActiveAsync(_active, ct);
        }
        finally { _gate.Release(); }
    }

    private bool HasSecretKey()
    {
        var psi = Base(["--batch", "--no-tty", "--list-secret-keys", "--with-colons"]);
        using var p = Process.Start(psi)!;
        var outp = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return outp.Contains("\nsec:") || outp.StartsWith("sec:");
    }

    private async Task GenerateKeyAsync(CancellationToken ct)
    {
        var pass = ReadPassphrase();
        var args = new List<string> { "--batch", "--no-tty", "--yes", "--pinentry-mode", "loopback" };
        var param = new StringBuilder();
        param.Append("Key-Type: EDDSA\nKey-Curve: ed25519\nKey-Usage: sign\nName-Real: RepoCuck\nName-Email: repocuck@localhost\nExpire-Date: 10y\n");
        if (string.IsNullOrEmpty(pass)) param.Append("%no-protection\n"); else param.Append("Passphrase: ").Append(pass).Append('\n');
        param.Append("%commit\n");
        args.AddRange(["--gen-key"]);
        await Run(args, param.ToString(), ct);
        await File.WriteAllTextAsync(Path.Combine(GnupgHome, "keys.generated"), "1", ct);
    }

    private string? ReadPassphrase()
    {
        var o = options.Value;
        if (!string.IsNullOrEmpty(o.SigningKeyPassphraseFile) && File.Exists(o.SigningKeyPassphraseFile))
            return File.ReadAllText(o.SigningKeyPassphraseFile).TrimEnd('\r', '\n');
        return o.SigningKeyPassphrase;
    }

    private async Task<string> FindFingerprintAsync(CancellationToken ct)
    {
        var (output, _) = await Run(["--batch", "--no-tty", "--list-secret-keys", "--with-colons", "--fingerprint"], null, ct);
        var lines = output.Split('\n');
        for (var i = 0; i < lines.Length; i++)
            if (lines[i].StartsWith("sec:", StringComparison.Ordinal))
                for (var j = i + 1; j < lines.Length; j++)
                    if (lines[j].StartsWith("fpr:", StringComparison.Ordinal)) return lines[j].Split(':')[9];
        throw new InvalidOperationException("No secret signing key available.");
    }

    public async Task<SigningResult> SignAsync(byte[] release, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var detached = await SignAsyncCore(release, detached: true, ct);
        var clear = await SignAsyncCore(release, detached: false, ct);
        return new SigningResult(clear, detached);
    }

    private async Task<byte[]> SignAsyncCore(byte[] data, bool detached, CancellationToken ct)
    {
        var dir = Path.Combine(storage.Value.Root, "tmp", "sign-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var input = Path.Combine(dir, "Release");
            var output = Path.Combine(dir, detached ? "Release.gpg" : "InRelease");
            await File.WriteAllBytesAsync(input, data, ct);
            var args = new List<string> { "--batch", "--no-tty", "--yes", "--pinentry-mode", "loopback" };
            var pass = ReadPassphrase();
            string? passFile = null;
            if (!string.IsNullOrEmpty(pass))
            {
                passFile = Path.Combine(dir, "pass");
                await File.WriteAllTextAsync(passFile, pass, ct);
                TryChmod(passFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                args.AddRange(["--passphrase-file", passFile]);
            }
            foreach (var fpr in _active.Count > 0 ? _active : (_fingerprint is null ? [] : [_fingerprint])) args.AddRange(["--local-user", fpr]);
            args.AddRange(["--digest-algo", "SHA512"]);
            if (detached) args.AddRange(["--armor", "--detach-sign"]); else args.Add("--clearsign");
            args.AddRange(["--output", output, input]);
            await Run(args, null, ct);
            return await File.ReadAllBytesAsync(output, ct);
        }
        finally { try { Directory.Delete(dir, true); } catch { /* ignore */ } }
    }

    public async Task<byte[]> ExportPublicKeyAsync(CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        return await RunBinary(["--batch", "--no-tty", "--export", .. _active], ct);
    }

    public async Task<byte[]> ExportPublicKeyArmoredAsync(CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        return await RunBinary(["--batch", "--no-tty", "--armor", "--export", .. _active], ct);
    }

    public async Task<DateTimeOffset?> GetKeyExpiryAsync(CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var (output, _) = await Run(["--batch", "--no-tty", "--list-keys", "--with-colons", _fingerprint!], null, ct);
        foreach (var l in output.Split('\n'))
            if (l.StartsWith("pub:", StringComparison.Ordinal))
            {
                var f = l.Split(':');
                if (f.Length > 6 && long.TryParse(f[6], out var exp) && exp > 0) return DateTimeOffset.FromUnixTimeSeconds(exp);
            }
        return null;
    }

    private ProcessStartInfo Base(IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo("gpg")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = null
        };
        psi.Environment["GNUPGHOME"] = GnupgHome;
        foreach (var a in args) psi.ArgumentList.Add(a);
        return psi;
    }

    private async Task<(string Output, string Error)> Run(IEnumerable<string> args, string? stdin, CancellationToken ct, bool passphrase = false)
    {
        var list = args.ToList();
        if (passphrase)
        {
            var pass = ReadPassphrase();
            if (!string.IsNullOrEmpty(pass))
            {
                var pf = Path.Combine(storage.Value.Root, "tmp", "pp-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(Path.GetDirectoryName(pf)!);
                await File.WriteAllTextAsync(pf, pass, ct);
                TryChmod(pf, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                try
                {
                    list.InsertRange(3, ["--pinentry-mode", "loopback", "--passphrase-file", pf]);
                    return await RunCore(list, stdin, ct);
                }
                finally { File.Delete(pf); }
            }
        }
        return await RunCore(list, stdin, ct);
    }

    private async Task<(string, string)> RunCore(List<string> args, string? stdin, CancellationToken ct)
    {
        using var p = Process.Start(Base(args))!;
        if (stdin is not null) await p.StandardInput.WriteAsync(stdin.AsMemory(), ct);
        p.StandardInput.Close();
        var o = p.StandardOutput.ReadToEndAsync(ct);
        var e = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        var (so, se) = (await o, await e);
        if (p.ExitCode != 0) throw new InvalidOperationException($"gpg failed ({p.ExitCode}): {se.Trim()}");
        return (so, se);
    }

    private async Task<byte[]> RunBinary(IEnumerable<string> args, CancellationToken ct)
    {
        using var p = Process.Start(Base(args))!;
        p.StandardInput.Close();
        using var ms = new MemoryStream();
        var copy = p.StandardOutput.BaseStream.CopyToAsync(ms, ct);
        var err = p.StandardError.ReadToEndAsync(ct);
        await copy;
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0) throw new InvalidOperationException($"gpg failed: {(await err).Trim()}");
        return ms.ToArray();
    }

    private static void TryChmod(string path, UnixFileMode mode)
    {
        try { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, mode); } catch { /* best effort */ }
    }
}
