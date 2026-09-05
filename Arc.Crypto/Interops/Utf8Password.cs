// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Arc.Crypto;

/// <summary>
/// Holds temporary UTF-8 password bytes and clears them before returning pooled storage.
/// </summary>
internal ref struct Utf8Password
{
    internal const int StackSize = 256;

    private byte[]? rented;
    private Span<byte> bytes;

    internal Utf8Password(ReadOnlySpan<char> password, Span<byte> buffer)
    {
        var length = Encoding.UTF8.GetByteCount(password);
        this.rented = length > buffer.Length ? ArrayPool<byte>.Shared.Rent(length) : null;
        this.bytes = (this.rented is null ? buffer : this.rented.AsSpan())[..length];
        Encoding.UTF8.GetBytes(password, this.bytes);
    }

    internal readonly ReadOnlySpan<byte> Bytes => this.bytes;

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(this.bytes);
        this.bytes = default;
        if (this.rented is { } buffer)
        {
            this.rented = null;
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
