// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Compares character arrays by ordinal content and supports <see cref="ReadOnlySpan{T}"/> alternate lookups.
/// </summary>
/// <remarks>
/// Hash codes are XXH3 values seeded randomly once per process, so they differ between processes and must not be persisted.
/// </remarks>
public sealed class Utf16StringEqualityComparer : IEqualityComparer<char[]>, IAlternateEqualityComparer<ReadOnlySpan<char>, char[]>
{
    // Shared by the array and span overloads so that both produce the same hash for the same content.
    private static readonly long Seed = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(sizeof(long)));
    private static readonly byte[] Secret = XxHash3.CreateSecret(Seed); // Avoids deriving the secret on every hash of a key over 240 bytes.

    /// <summary>
    /// Gets the default instance of <see cref="Utf16StringEqualityComparer"/>.
    /// </summary>
    public static IEqualityComparer<char[]> Default { get; } = new Utf16StringEqualityComparer();

    /// <summary>
    /// Determines whether two character arrays contain the same characters (ordinal comparison).
    /// </summary>
    /// <param name="x">The first character array to compare.</param>
    /// <param name="y">The second character array to compare.</param>
    /// <returns><see langword="true"/> if both are <see langword="null"/> or have the same contents; otherwise, <see langword="false"/>.</returns>
    public bool Equals(char[]? x, char[]? y)
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
    /// Returns a hash code for the contents of the specified character array.
    /// </summary>
    /// <param name="obj">The character array for which to get the hash code.</param>
    /// <returns>A hash code for the contents of <paramref name="obj"/>, equal to <see cref="GetHashCode(ReadOnlySpan{char})"/> for the same characters.</returns>
    public int GetHashCode([DisallowNull] char[] obj)
        => unchecked((int)XxHash3.Hash64(MemoryMarshal.AsBytes(obj.AsSpan()), Seed, Secret));

    /// <summary>
    /// Creates a new character array from the specified read-only span of characters.
    /// </summary>
    /// <param name="alternate">The read-only span of characters to convert.</param>
    /// <returns>A new character array containing the characters from the span.</returns>
    public char[] Create(ReadOnlySpan<char> alternate)
        => alternate.ToArray();

    /// <summary>
    /// Determines whether a read-only span of characters and a character array contain the same characters (ordinal comparison).
    /// </summary>
    /// <param name="alternate">The read-only span of characters to compare.</param>
    /// <param name="other">The character array to compare.</param>
    /// <returns><see langword="true"/> if <paramref name="other"/> is not <see langword="null"/> and has the same contents as <paramref name="alternate"/>; otherwise, <see langword="false"/>.</returns>
    public bool Equals(ReadOnlySpan<char> alternate, char[] other)
        => other is not null && other.AsSpan().SequenceEqual(alternate);

    /// <summary>
    /// Returns a hash code for the specified read-only span of characters.
    /// </summary>
    /// <param name="alternate">The read-only span of characters for which to get the hash code.</param>
    /// <returns>A hash code for <paramref name="alternate"/>, equal to <see cref="GetHashCode(char[])"/> for the same characters.</returns>
    public int GetHashCode(ReadOnlySpan<char> alternate)
        => unchecked((int)XxHash3.Hash64(MemoryMarshal.AsBytes(alternate), Seed, Secret));
}
