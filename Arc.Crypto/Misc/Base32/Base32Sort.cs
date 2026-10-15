// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

/// <summary>
/// Provides unpadded Base32 encoding whose output keeps the byte order of the source under ordinal comparison.<br/>
/// The alphabet <c>0123456789ABCEFGHJKMNPQRSTUVWXYZ</c> omits the ambiguous letters <c>D</c>, <c>I</c>, <c>L</c> and <c>O</c>.
/// </summary>
/// <remarks>
/// Decoding accepts lower-case letters, maps <c>I</c>, <c>i</c> and <c>l</c> to <c>1</c> and <c>O</c> and <c>o</c> to <c>0</c>, and rejects <c>D</c>, <c>d</c> and <c>L</c>.<br/>
/// Decoding is lenient: trailing bits that do not complete a byte are ignored, whether they are the unused low bits of a character
/// or a whole trailing character (lengths of 1, 3 or 6 modulo 8), which must still be valid.
/// Strings the encoder never produces can therefore decode successfully; for example, <c>04</c> to <c>07</c> all decode to <c>0x01</c>, and <c>0</c> decodes to no bytes.
/// </remarks>
public static class Base32Sort
{
    private static readonly char[] Utf16EncodeTable =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'E', 'F', 'G', 'H', 'J', 'K', 'M',
        'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z',
    };

    private static readonly byte[] Utf8EncodeTable;
    private static readonly byte[] DecodeTable;

    static Base32Sort()
    {
        // Prepare tables
        Utf8EncodeTable = new byte[Utf16EncodeTable.Length];
        for (var i = 0; i < Utf8EncodeTable.Length; i++)
        {
            Utf8EncodeTable[i] = (byte)Utf16EncodeTable[i];
        }

        // The table is indexed by a whole byte/latin-1 char, so it must hold 256 entries.
        DecodeTable = new byte[byte.MaxValue + 1];
        for (var i = 0; i < DecodeTable.Length; i++)
        {
            DecodeTable[i] = byte.MaxValue;
        }

        byte b = 0;
        foreach (var x in Utf8EncodeTable)
        {
            DecodeTable[x] = b++;
            if (x >= (byte)'A' && x <= (byte)'Z')
            {
                DecodeTable[x - (byte)'A' + (byte)'a'] = DecodeTable[x];
            }
        }

        DecodeTable['I'] = DecodeTable['1']; // I -> 1
        DecodeTable['i'] = DecodeTable['1']; // i -> 1
        DecodeTable['l'] = DecodeTable['1']; // l -> 1
        DecodeTable['O'] = DecodeTable['0']; // O -> 0
        DecodeTable['o'] = DecodeTable['0']; // o -> 0

        Reference = new Base32SortReference(Utf16EncodeTable, Utf8EncodeTable, DecodeTable);
        Table = new Base32SortTable(Utf16EncodeTable, Utf8EncodeTable, DecodeTable);
        Default = Table;
    }

    /// <summary>
    /// The recommended converter, currently the same instance as <see cref="Table"/>.
    /// </summary>
    public static readonly IBase32Converter Default;

    /// <summary>
    /// A straightforward converter kept as the behavioral reference for <see cref="Table"/>.
    /// </summary>
    public static readonly IBase32Converter Reference;

    /// <summary>
    /// An unrolled, pointer-based converter that handles five bytes (eight characters) per step.
    /// </summary>
    public static readonly IBase32Converter Table;

    /// <summary>
    /// Gets the number of Base32 characters produced by encoding <paramref name="sourceLength"/> bytes (no padding).
    /// </summary>
    /// <param name="sourceLength">The number of source bytes.</param>
    /// <returns>The encoded length in characters.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sourceLength"/> is negative, or the encoded length exceeds <see cref="int.MaxValue"/>.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int sourceLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sourceLength);
        var length = (((long)sourceLength * 8) + 4) / 5;
        if (length > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(sourceLength), "Encoded length exceeds Int32.MaxValue.");
        }

        return (int)length;
    }

    /// <summary>
    /// Gets the number of bytes produced by decoding <paramref name="encodedLength"/> Base32 characters.
    /// </summary>
    /// <param name="encodedLength">The number of encoded characters.</param>
    /// <returns>The decoded length in bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="encodedLength"/> is negative.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetDecodedLength(int encodedLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(encodedLength);
        return (int)(((long)encodedLength * 5) >> 3);
    }

    /// <summary>
    /// Computes <paramref name="value"/> modulo 5, using a multiplication instead of a division on 64-bit processes.
    /// </summary>
    /// <param name="value">The value to reduce. It is treated as an unsigned 32-bit integer, so a negative value is reduced as <c>(uint)value</c>.</param>
    /// <returns>The remainder of <c>(uint)value</c> divided by 5, from 0 to 4.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FastMod5(int value)
    {
        if (Environment.Is64BitProcess)
        {
            return Mod5ByMultiplication(value);
        }
        else
        {
            return Mod5ByDivision(value);
        }
    }

    /// <summary>
    /// The 64-bit path of <see cref="FastMod5(int)"/>: computes <c>(uint)value % 5</c> with a 64-bit multiplication.
    /// </summary>
    /// <param name="value">The value to reduce, treated as an unsigned 32-bit integer.</param>
    /// <returns>The remainder, from 0 to 4.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int Mod5ByMultiplication(int value)
    {
        ulong lowbits = ((ulong.MaxValue / 5) + 1) * (uint)value;
        uint highbits = (uint)Math.BigMul(lowbits, 5, out _);
        return (int)highbits;
    }

    /// <summary>
    /// The 32-bit path of <see cref="FastMod5(int)"/>: computes <c>(uint)value % 5</c> with a division.
    /// </summary>
    /// <param name="value">The value to reduce, treated as an unsigned 32-bit integer.</param>
    /// <returns>The remainder, from 0 to 4.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int Mod5ByDivision(int value)
        => (int)((uint)value % 5u);
}
