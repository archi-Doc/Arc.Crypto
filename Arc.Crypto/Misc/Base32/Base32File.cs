// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

public static class Base32File
{
    private static readonly char[] Utf16EncodeTable =
    {
        '#', '$', '+', '-', '@',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M','N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z',
        '_',
    };

    private static readonly byte[] Utf8EncodeTable;
    private static readonly byte[] DecodeTable;

    static Base32File()
    {
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

        Default = new Base32SortTable(Utf16EncodeTable, Utf8EncodeTable, DecodeTable);
    }

    public static readonly IBaseConverter Default;
}
