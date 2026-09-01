// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

/// <summary>
/// Provides Base32 encoding and decoding using an alphabet that preserves the sort order of the encoded data.<br/>
/// The alphabet omits the ambiguous characters <c>D</c>, <c>I</c>, <c>L</c> and <c>O</c>; when decoding,
/// <c>I</c>/<c>l</c> map to <c>1</c>, <c>O</c> maps to <c>0</c>, and lower-case input is accepted.
/// </summary>
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
    /// A table-driven converter that processes eight characters at a time.
    /// </summary>
    public static readonly IBase32Converter Table;

    /// <summary>
    /// Get the length of the base32 encoded data.
    /// </summary>
    /// <param name="sourceLength">The source length.</param>
    /// <returns>The base32 encoded length of <paramref name="sourceLength"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int sourceLength)
        => ((sourceLength << 3) + 4) / 5;

    /// <summary>
    /// Gets the length of the decoded data.
    /// </summary>
    /// <param name="encodedLength">The encoded length.</param>
    /// <returns>The base32 decoded length of <paramref name="encodedLength"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetDecodedLength(int encodedLength)
        => (encodedLength * 5) >> 3;

    /// <summary>
    /// Computes <paramref name="value"/> modulo 5, using a multiplication instead of a division on 64-bit processes.
    /// </summary>
    /// <param name="value">The non-negative value to reduce.</param>
    /// <returns>The remainder of <paramref name="value"/> divided by 5.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FastMod5(int value)
    {
        if (Environment.Is64BitProcess)
        {
            ulong lowbits = ((ulong.MaxValue / 5) + 1) * (uint)value;
            uint highbits = (uint)Math.BigMul(lowbits, 5, out _);
            return (int)highbits;
        }
        else
        {
            return value % 5;
        }
    }
}
