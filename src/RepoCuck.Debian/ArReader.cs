using System.Text;

namespace RepoCuck.Debian;

public sealed record ArMember(string Name, long Size, long DataOffset);

public sealed class DebFormatException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>Minimal, bounded reader for the ar container used by .deb files.</summary>
public static class ArReader
{
    public static readonly byte[] Magic = "!<arch>\n"u8.ToArray();
    public const int MaxMembers = 16;

    public static bool HasMagic(ReadOnlySpan<byte> head) => head.Length >= 8 && head[..8].SequenceEqual(Magic);

    /// <summary>Enumerates members without reading payloads. Stream must be seekable.</summary>
    public static List<ArMember> ReadMembers(Stream s, long maxMemberSize)
    {
        if (!s.CanSeek) throw new ArgumentException("Stream must be seekable.", nameof(s));
        s.Position = 0;
        Span<byte> head = stackalloc byte[8];
        if (s.Read(head) != 8 || !HasMagic(head)) throw new DebFormatException("not_ar", "Missing ar magic.");
        var members = new List<ArMember>();
        var length = s.Length;
        Span<byte> hdr = stackalloc byte[60];
        while (s.Position < length)
        {
            if (members.Count >= MaxMembers) throw new DebFormatException("too_many_members", "Too many ar members.");
            var read = s.Read(hdr);
            if (read == 0) break;
            if (read != 60)
            {
                if (IsAllZero(hdr[..read])) break;
                throw new DebFormatException("truncated_header", "Truncated ar header.");
            }
            if (hdr[58] != (byte)'`' || hdr[59] != (byte)'\n')
                throw new DebFormatException("bad_header", "Bad ar member terminator.");
            var rawName = Encoding.ASCII.GetString(hdr[..16]).TrimEnd(' ');
            var sizeText = Encoding.ASCII.GetString(hdr.Slice(48, 10)).Trim();
            if (sizeText.Length == 0 || !sizeText.All(char.IsAsciiDigit) || !long.TryParse(sizeText, out var size))
                throw new DebFormatException("bad_size", "Non-numeric ar member size.");
            var dataOffset = s.Position;
            var name = rawName;
            if (rawName.StartsWith("#1/", StringComparison.Ordinal))
            {
                if (!int.TryParse(rawName.AsSpan(3), out var nameLen) || nameLen < 1 || nameLen > 255 || nameLen > size)
                    throw new DebFormatException("bad_name", "Bad BSD ar name length.");
                var nameBytes = new byte[nameLen];
                s.ReadExactly(nameBytes);
                name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                dataOffset += nameLen;
                size -= nameLen;
            }
            else if (name.EndsWith('/') && name.Length > 1)
            {
                name = name[..^1];
            }
            if (size > maxMemberSize) throw new DebFormatException("member_too_large", "ar member exceeds size cap.");
            if (dataOffset + size > length) throw new DebFormatException("truncated_member", "ar member exceeds file.");
            members.Add(new ArMember(name, size, dataOffset));
            var next = dataOffset + size;
            if (next % 2 == 1) next++;
            if (next >= length) break;
            s.Position = next;
        }
        return members;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> b)
    {
        foreach (var x in b) if (x != 0) return false;
        return true;
    }
}
