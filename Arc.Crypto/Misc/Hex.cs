// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;

namespace Arc.Crypto;

/// <summary>
/// Provides conversion between byte sequences and lower-case hexadecimal strings.
/// </summary>
public static class Hex
{
#pragma warning disable SA1311 // Static readonly fields should begin with upper-case letter
    private static readonly char[] encodingTable = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', };
#pragma warning restore SA1311 // Static readonly fields should begin with upper-case letter

    /// <summary>
    /// Converts a byte sequence to a lower-case hexadecimal string.
    /// </summary>
    /// <param name="bytes">The bytes to convert.</param>
    /// <returns>A hexadecimal string twice as long as <paramref name="bytes"/>.</returns>
    public static string FromByteArrayToString(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.Length * 2;
        char[]? pooledName = null;
        scoped Span<char> c = length <= 1024 ?
            stackalloc char[length] : (pooledName = ArrayPool<char>.Shared.Rent(length)).AsSpan(0, length);

        try
        {
            var i = 0;
            foreach (var x in bytes)
            {
                c[i++] = encodingTable[x >> 4];
                c[i++] = encodingTable[x & 0xF];
            }

            return new string(c);
        }
        finally
        {
            if (pooledName is not null)
            {
                ArrayPool<char>.Shared.Return(pooledName);
            }
        }
    }

    /// <summary>
    /// Converts a hexadecimal string to a byte array.<br/>
    /// Both upper-case and lower-case digits are accepted. For performance reasons the input is not validated,
    /// and characters outside <c>0-9</c>, <c>a-f</c> and <c>A-F</c> produce unspecified bytes.
    /// </summary>
    /// <param name="str">The hexadecimal string to convert. Its length must be even.</param>
    /// <returns>A byte array half as long as <paramref name="str"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the length of <paramref name="str"/> is odd.</exception>
    public static byte[] FromStringToByteArray(string str)
    {
        if ((str.Length & 1) != 0)
        {
            throw new ArgumentException($"The length of {nameof(str)} must be even.", nameof(str));
        }

        ReadOnlySpan<char> span = str.AsSpan();
        var result = new byte[str.Length / 2];
        for (var i = 0; i < result.Length; i++)
        {
            int high = span[i * 2];
            int low = span[(i * 2) + 1];
            high = (high & 0xf) + (((high & 0x40) >> 6) * 9);
            low = (low & 0xf) + (((low & 0x40) >> 6) * 9);

            result[i] = (byte)((high << 4) | low);
        }

        return result;
    }
}
