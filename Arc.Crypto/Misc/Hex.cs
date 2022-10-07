// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;

namespace Arc.Crypto;

public static class Hex
{
#pragma warning disable SA1311 // Static readonly fields should begin with upper-case letter
    private static readonly char[] encodingTable = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', };
#pragma warning restore SA1311 // Static readonly fields should begin with upper-case letter

    public static string FromByteArrayToString(ReadOnlySpan<byte> bytes)
    {
        var length = bytes.Length * 2;
        char[]? pooledName = null;
        scoped Span<char> c = length <= 1024 ?
            stackalloc char[length] : (pooledName = ArrayPool<char>.Shared.Rent(length));

        var i = 0;
        foreach (var x in bytes)
        {
            var y = (int)x;
            c[i++] = encodingTable[x >> 4];
            c[i++] = encodingTable[x & 0xF];
        }

        var str = new string(c);

        if (pooledName != null)
        {
            ArrayPool<char>.Shared.Return(pooledName);
        }

        return str;
    }

    public static byte[] FromStringToByteArray(string str)
    {
        if ((str.Length & 1) != 0)
        {
            throw new ArgumentException();
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
