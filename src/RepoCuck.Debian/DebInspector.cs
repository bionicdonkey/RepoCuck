using System.Formats.Tar;
using System.IO.Compression;
using SharpCompress.Compressors.BZip2;
using SharpCompress.Compressors.Xz;

namespace RepoCuck.Debian;

public sealed record DebInfo(ControlFile Control, string ControlArchiveName);

/// <summary>Reads only the control metadata of a .deb with bounded decompression; never touches data.tar.*.</summary>
public static class DebInspector
{
    public const long MaxControlArchive = 8L * 1024 * 1024;
    public const int MaxControlFile = 256 * 1024;
    public const long MaxDecompressed = 16L * 1024 * 1024;
    public const int MaxRatio = 200;
    public const int MaxTarEntries = 64;

    public static DebInfo Inspect(Stream deb, long maxAssetBytes)
    {
        var members = ArReader.ReadMembers(deb, maxAssetBytes + 1024 * 1024);
        var bin = members.FirstOrDefault(m => m.Name == "debian-binary")
                  ?? throw new DebFormatException("no_debian_binary", "debian-binary member missing.");
        if (bin.Size > 16) throw new DebFormatException("bad_debian_binary", "debian-binary too large.");
        deb.Position = bin.DataOffset;
        var buf = new byte[bin.Size];
        deb.ReadExactly(buf);
        if (!System.Text.Encoding.ASCII.GetString(buf).StartsWith("2.0", StringComparison.Ordinal))
            throw new DebFormatException("unsupported_format", "Unsupported .deb format version.");

        var ctrl = members.FirstOrDefault(m => m.Name.StartsWith("control.tar", StringComparison.Ordinal))
                   ?? throw new DebFormatException("no_control", "control.tar member missing.");
        if (ctrl.Size > MaxControlArchive) throw new DebFormatException("control_too_large", "control archive too large.");

        deb.Position = ctrl.DataOffset;
        var compressed = new byte[ctrl.Size];
        deb.ReadExactly(compressed);
        using var input = new MemoryStream(compressed, writable: false);
        using var decoded = Decode(ctrl.Name, input);
        using var bounded = new BoundedReadStream(decoded, Math.Min(MaxDecompressed, Math.Max(ctrl.Size * MaxRatio, 64 * 1024)));
        byte[]? controlBytes = null;
        try
        {
            using var tar = new TarReader(bounded, leaveOpen: true);
            var entries = 0;
            while (tar.GetNextEntry(copyData: false) is { } entry)
            {
                if (++entries > MaxTarEntries) throw new DebFormatException("too_many_entries", "control.tar has too many entries.");
                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)) continue;
                var n = entry.Name.StartsWith("./", StringComparison.Ordinal) ? entry.Name[2..] : entry.Name;
                if (n != "control") continue;
                if (entry.Length > MaxControlFile) throw new DebFormatException("control_too_large", "control file too large.");
                using var ms = new MemoryStream();
                entry.DataStream!.CopyTo(ms);
                controlBytes = ms.ToArray();
                break;
            }
        }
        catch (InvalidDataException e) { throw new DebFormatException("bad_control_tar", e.Message); }
        catch (IOException e) when (e is not EndOfStreamException) { throw new DebFormatException("bad_control_tar", e.Message); }
        catch (EndOfStreamException e) { throw new DebFormatException("bad_control_tar", e.Message); }
        if (controlBytes is null) throw new DebFormatException("no_control_file", "control file missing from control.tar.");
        return new DebInfo(ControlParser.Parse(controlBytes), ctrl.Name);
    }

    private static Stream Decode(string name, Stream input)
    {
        if (name == "control.tar") return input;
        if (name.EndsWith(".gz", StringComparison.Ordinal)) return new GZipStream(input, System.IO.Compression.CompressionMode.Decompress);
        if (name.EndsWith(".xz", StringComparison.Ordinal)) return new XZStream(input);
        if (name.EndsWith(".bz2", StringComparison.Ordinal)) return new BZip2Stream(input, SharpCompress.Compressors.CompressionMode.Decompress, false);
        if (name.EndsWith(".zst", StringComparison.Ordinal)) return new ZstdSharp.DecompressionStream(input);
        throw new DebFormatException("unsupported_compression", $"Unsupported control archive '{name}'.");
    }

    private sealed class BoundedReadStream(Stream inner, long limit) : Stream
    {
        private long _total;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            var n = inner.Read(buffer);
            _total += n;
            if (_total > limit) throw new DebFormatException("decompression_limit", "control.tar exceeds decompression limits.");
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
