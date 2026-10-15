// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Compares byte arrays, typically UTF-8 text, by content and supports <see cref="ReadOnlySpan{T}"/> alternate lookups.
/// </summary>
/// <remarks>
/// Hash codes are XXH3 values seeded randomly once per process, so they differ between processes and must not be persisted.
/// </remarks>
public sealed class Utf8StringEqualityComparer : IEqualityComparer<byte[]>, IAlternateEqualityComparer<ReadOnlySpan<byte>, byte[]>
{
    // Shared by the array and span overloads so that both produce the same hash for the same content.
    private static readonly long Seed = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(sizeof(long)));
    private static readonly byte[] Secret = XxHash3.CreateSecret(Seed); // Avoids deriving the secret on every hash of a key over 240 bytes.

    /// <summary>
    /// Gets the default instance of <see cref="Utf8StringEqualityComparer"/>.
    /// </summary>
    public static IEqualityComparer<byte[]> Default { get; } = new Utf8StringEqualityComparer();

    /// <summary>
    /// Determines whether two byte arrays contain the same bytes.
    /// </summary>
    /// <param name="x">The first byte array to compare.</param>
    /// <param name="y">The second byte array to compare.</param>
    /// <returns><see langword="true"/> if both are <see langword="null"/> or have the same contents; otherwise, <see langword="false"/>.</returns>
    public bool Equals(byte[]? x, byte[]? y)
    {
        if (x is null && y is null)
        {
            return true;
        }

        if (x is null || y is null)
        {
            return false;
        }

        return x.AsSpan().SequenceEqual(y);
    }

    /// <summary>
    /// Returns a hash code for the contents of the specified byte array.
    /// </summary>
    /// <param name="obj">The byte array for which to get the hash code.</param>
    /// <returns>A hash code for the contents of <paramref name="obj"/>, equal to <see cref="GetHashCode(ReadOnlySpan{byte})"/> for the same bytes.</returns>
    public int GetHashCode([DisallowNull] byte[] obj)
        => unchecked((int)XxHash3.Hash64(obj.AsSpan(), Seed, Secret));

    /// <summary>
    /// Creates a new byte array from the specified read-only span of bytes.
    /// </summary>
    /// <param name="alternate">The read-only span of bytes to convert.</param>
    /// <returns>A new byte array containing the data from the span.</returns>
    public byte[] Create(ReadOnlySpan<byte> alternate)
        => alternate.ToArray();

    /// <summary>
    /// Determines whether a read-only span of bytes and a byte array contain the same bytes.
    /// </summary>
    /// <param name="alternate">The read-only span of bytes to compare.</param>
    /// <param name="other">The byte array to compare.</param>
    /// <returns><see langword="true"/> if <paramref name="other"/> is not <see langword="null"/> and has the same contents as <paramref name="alternate"/>; otherwise, <see langword="false"/>.</returns>
    public bool Equals(ReadOnlySpan<byte> alternate, byte[] other)
        => other is not null && other.AsSpan().SequenceEqual(alternate);

    /// <summary>
    /// Returns a hash code for the specified read-only span of bytes.
    /// </summary>
    /// <param name="alternate">The read-only span of bytes for which to get the hash code.</param>
    /// <returns>A hash code for <paramref name="alternate"/>, equal to <see cref="GetHashCode(byte[])"/> for the same bytes.</returns>
    public int GetHashCode(ReadOnlySpan<byte> alternate)
        => unchecked((int)XxHash3.Hash64(alternate, Seed, Secret));
}
