// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

/// <summary>
/// Provides conversion between byte sequences and lower-case hexadecimal strings.
/// </summary>
public static class Hex
{
    /// <summary>
    /// Converts a byte sequence to a lower-case hexadecimal string.
    /// </summary>
    /// <param name="bytes">The bytes to convert.</param>
    /// <returns>A hexadecimal string twice as long as <paramref name="bytes"/>.</returns>
    public static string FromBytesToString(ReadOnlySpan<byte> bytes)
        => Convert.ToHexStringLower(bytes); // Vectorized in the BCL, and writes straight into the string.

    /// <summary>
    /// Converts a hexadecimal string to a byte array.<br/>
    /// Both upper-case and lower-case digits are accepted.
    /// </summary>
    /// <param name="hex">The hexadecimal string to convert. Its length must be even.</param>
    /// <returns>A byte array half as long as <paramref name="hex"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="hex"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the length of <paramref name="hex"/> is odd.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="hex"/> contains a character outside <c>0-9</c>, <c>a-f</c> and <c>A-F</c>.</exception>
    public static byte[] FromStringToByteArray(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if ((hex.Length & 1) != 0)
        {
            throw new ArgumentException($"The length of {nameof(hex)} must be even.", nameof(hex));
        }

        return Convert.FromHexString(hex); // Vectorized in the BCL, and validates every digit.
    }
}
