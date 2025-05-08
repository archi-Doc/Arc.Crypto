// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics.CodeAnalysis;

namespace Arc.Crypto;

/// <summary>
/// Provides an equality comparer for UTF-16 encoded strings represented as character arrays.
/// </summary>
public sealed class Utf16StringEqualityComparer : IEqualityComparer<char[]>, IAlternateEqualityComparer<ReadOnlySpan<char>, char[]>
{
    /// <summary>
    /// Gets the default instance of <see cref="Utf16StringEqualityComparer"/>.
    /// </summary>
    public static IEqualityComparer<char[]> Default { get; } = new Utf16StringEqualityComparer();

    /// <summary>
    /// Determines whether two character arrays are equal.
    /// </summary>
    /// <param name="x">The first character array to compare.</param>
    /// <param name="y">The second character array to compare.</param>
    /// <returns><c>true</c> if the character arrays are equal; otherwise, <c>false</c>.</returns>
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
    /// Returns a hash code for the specified character array.
    /// </summary>
    /// <param name="obj">The character array for which to get the hash code.</param>
    /// <returns>A hash code for the specified character array.</returns>
    public int GetHashCode([DisallowNull] char[] obj)
        => unchecked((int)XxHash3.Hash64(obj.AsSpan()));

    /// <summary>
    /// Creates a new character array from the specified read-only span of characters.
    /// </summary>
    /// <param name="alternate">The read-only span of characters to convert.</param>
    /// <returns>A new character array containing the characters from the span.</returns>
    public char[] Create(ReadOnlySpan<char> alternate)
        => alternate.ToArray();

    /// <summary>
    /// Determines whether a read-only span of characters and a character array are equal.
    /// </summary>
    /// <param name="alternate">The read-only span of characters to compare.</param>
    /// <param name="other">The character array to compare.</param>
    /// <returns><c>true</c> if the span and array are equal; otherwise, <c>false</c>.</returns>
    public bool Equals(ReadOnlySpan<char> alternate, char[] other)
        => other.AsSpan().SequenceEqual(alternate);

    /// <summary>
    /// Returns a hash code for the specified read-only span of characters.
    /// </summary>
    /// <param name="alternate">The read-only span of characters for which to get the hash code.</param>
    /// <returns>A hash code for the specified span of characters.</returns>
    public int GetHashCode(ReadOnlySpan<char> alternate)
        => unchecked((int)XxHash3.Hash64(alternate));
}
