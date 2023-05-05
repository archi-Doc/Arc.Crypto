// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

public static class Base32Sort
{
    internal static readonly char[] Utf16EncodeTable =
    {
        '2', '3', '4', '5', '6', '7',
        'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z',
    };

    internal static readonly byte[] Utf8EncodeTable;
    internal static readonly byte[] DecodeTable;

    static Base32Sort()
    {
        Reference = new Base32SortReference();
        Table = new Base32SortTable();
        Default = Table;

        // Prepare tables
        Utf8EncodeTable = new byte[Utf16EncodeTable.Length];
        for (var i = 0; i < Utf8EncodeTable.Length; i++)
        {
            Utf8EncodeTable[i] = (byte)Utf16EncodeTable[i];
        }

        DecodeTable = new byte[byte.MaxValue];
        for (byte i = 0; i < DecodeTable.Length; i++)
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
    }

    public static readonly IBaseConverter Default;
    public static readonly IBaseConverter Reference;
    public static readonly IBaseConverter Table;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int length)
        => ((length << 3) + 4) / 5;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetDecodedLength(int length)
        => (length * 5) >> 3;

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
