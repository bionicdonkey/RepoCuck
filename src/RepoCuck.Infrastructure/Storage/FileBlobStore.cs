using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using RepoCuck.Application;

namespace RepoCuck.Infrastructure.Storage;

public sealed class FileBlobStore : IBlobStore
{
    private readonly string _root;
    public string TempDirectory { get; }

    public FileBlobStore(IOptions<StorageOptions> options)
    {
        _root = Path.Combine(options.Value.Root, "blobs", "sha256");
        TempDirectory = Path.Combine(options.Value.Root, "tmp");
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(TempDirectory);
    }

    public static string KeyFor(string sha256) => $"{sha256[..2]}/{sha256[2..4]}/{sha256}";
    private string PathFor(string key)
    {
        if (key.Contains("..") || key.StartsWith('/')) throw new ArgumentException("bad key");
        return Path.Combine(_root, key);
    }

    public Task<StoredBlob> AdoptFileAsync(string tempPath, string sha256, string sha512, long size, CancellationToken ct)
    {
        var key = KeyFor(sha256);
        var dest = PathFor(key);
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        if (File.Exists(dest)) { File.Delete(tempPath); }
        else
        {
            using (var fs = new FileStream(tempPath, FileMode.Open, FileAccess.ReadWrite)) fs.Flush(true);
            File.Move(tempPath, dest);
            TrySetMode(dest);
        }
        return Task.FromResult(new StoredBlob(sha256, sha512, size, key));
    }

    public async Task<StoredBlob> PutAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        var sha256 = Convert.ToHexStringLower(SHA256.HashData(data.Span));
        var sha512 = Convert.ToHexStringLower(SHA512.HashData(data.Span));
        var key = KeyFor(sha256);
        var dest = PathFor(key);
        if (!File.Exists(dest))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            var tmp = Path.Combine(TempDirectory, Guid.NewGuid().ToString("N") + ".tmp");
            await using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write))
            {
                await fs.WriteAsync(data, ct);
                fs.Flush(true);
            }
            File.Move(tmp, dest, overwrite: true);
            TrySetMode(dest);
        }
        return new StoredBlob(sha256, sha512, data.Length, key);
    }

    public Stream OpenRead(string storageKey) =>
        new FileStream(PathFor(storageKey), FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan);

    public bool Exists(string storageKey) => File.Exists(PathFor(storageKey));

    public Task DeleteAsync(string storageKey, CancellationToken ct)
    {
        var p = PathFor(storageKey);
        if (File.Exists(p)) File.Delete(p);
        return Task.CompletedTask;
    }

    private static void TrySetMode(string path)
    {
        try { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead); }
        catch { /* best effort */ }
    }
}
