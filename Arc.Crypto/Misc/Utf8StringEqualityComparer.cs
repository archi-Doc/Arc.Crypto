// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;

namespace Arc.Crypto;

/// <summary>
/// Provides an equality comparer for UTF-8 encoded byte arrays and spans.
/// </summary>
public sealed class Utf8StringEqualityComparer : IEqualityComparer<byte[]>, IAlternateEqualityComparer<ReadOnlySpan<byte>, byte[]>
{
    /// <summary>
    /// Gets the default instance of <see cref="Utf8StringEqualityComparer"/>.
    /// </summary>
    public static IEqualityComparer<byte[]> Default { get; } = new Utf8StringEqualityComparer();

    /// <summary>
    /// Determines whether two UTF-8 encoded byte arrays are equal.
    /// </summary>
    /// <param name="x">The first byte array to compare.</param>
    /// <param name="y">The second byte array to compare.</param>
    /// <returns><c>true</c> if the byte arrays are equal; otherwise, <c>false</c>.</returns>
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
    /// Returns a hash code for the specified UTF-8 encoded byte array.
    /// </summary>
    /// <param name="obj">The byte array for which to get the hash code.</param>
    /// <returns>A hash code for the specified byte array.</returns>
    public int GetHashCode([DisallowNull] byte[] obj)
        => unchecked((int)XxHash3.Hash64(obj.AsSpan()));

    /// <summary>
    /// Creates a new byte array from the specified read-only span of bytes.
    /// </summary>
    /// <param name="alternate">The read-only span of bytes to convert.</param>
    /// <returns>A new byte array containing the data from the span.</returns>
    public byte[] Create(ReadOnlySpan<byte> alternate)
        => alternate.ToArray();

    /// <summary>
    /// Determines whether a read-only span of bytes and a byte array are equal.
    /// </summary>
    /// <param name="alternate">The read-only span of bytes to compare.</param>
    /// <param name="other">The byte array to compare.</param>
    /// <returns><c>true</c> if the span and the byte array are equal; otherwise, <c>false</c>.</returns>
    public bool Equals(ReadOnlySpan<byte> alternate, byte[] other)
        => other.AsSpan().SequenceEqual(alternate);

    /// <summary>
    /// Returns a hash code for the specified read-only span of bytes.
    /// </summary>
    /// <param name="alternate">The read-only span of bytes for which to get the hash code.</param>
    /// <returns>A hash code for the specified span.</returns>
    public int GetHashCode(ReadOnlySpan<byte> alternate)
        => unchecked((int)XxHash3.Hash64(alternate));
}
