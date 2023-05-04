// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

public interface IBase32
{
    static abstract byte[] FromStringToByteArray(ReadOnlySpan<char> base32);
}

public class Base32SortReference : IBase32
{
    public static byte[] FromStringToByteArray(ReadOnlySpan<char> base32)
    {
        nint byteCount = Base32Sort.GetDecodedLength(base32.Length);
        byte[] returnArray = new byte[byteCount];

        byte current = 0;
        var remaining = 8;
        nint mask;
        nint arrayIndex = 0;

        foreach (char c in base32)
        {
            nint v = CharToValue(c);
            if (v < 0)
            {// Invalid character
                return Array.Empty<byte>();
            }

            if (remaining > 5)
            {
                mask = v << (remaining - 5);
                current = (byte)(current | mask);
                remaining -= 5;
            }
            else
            {
                mask = v >> (5 - remaining);
                current = (byte)(current | mask);
                returnArray[arrayIndex++] = current;
                current = (byte)(v << (3 + remaining));
                remaining += 3;
            }
        }

        if (arrayIndex != byteCount)
        {
            returnArray[arrayIndex] = current;
        }

        return returnArray;
    }

    public static unsafe string FromByteArrayToString(ReadOnlySpan<byte> bytes)
    {
        var length = Base32Sort.GetEncodedLength(bytes.Length);
        char[]? pooledName = null;

        Span<char> span = length <= 1024 ?
            stackalloc char[length] :
            (pooledName = ArrayPool<char>.Shared.Rent(length));

        byte next = 0;
        var remaining = 5;
        var index = 0;

        foreach (var b in bytes)
        {
            next = (byte)(next | (b >> (8 - remaining)));
            span[index++] = ValueToChar(next);

            if (remaining < 4)
            {
                next = (byte)((b >> (3 - remaining)) & 31);
                span[index++] = ValueToChar(next);
                remaining += 5;
            }

            remaining -= 3;
            next = (byte)((b << remaining) & 31);
        }

        if (index != length)
        {
            span[index++] = ValueToChar(next);
        }

        var result = new string(span);

        if (pooledName != null)
        {
            ArrayPool<char>.Shared.Return(pooledName);
        }

        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static nint CharToValue(char c)
    {
        var value = (nint)c;

        if (value >= 50 && value <= 55)
        {// '2' 50 - '7' 55 -> 0-5
            return value - 50;
        }
        else if (value >= 65 && value <= 90)
        {// 'A' 65 0x41 - 'Z' 90 0x5A -> 6-31
            return value - 59;
        }
        else if (value >= 65 && value <= 90)
        {// 'a' 97 0x61 - 'z' 122 0x7A -> 6-31
            return value - 91;
        }

        return -1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static char ValueToChar(byte b)
    {
        if (b < 6)
        {// 0-5 -> '2' 50 - '7' 55
            return (char)(b + 50);
        }
        else if (b < 32)
        {// 6-31 -> 'A' 65 0x41 - 'Z' 90 0x5A
            return (char)(b + 59);
        }

        return (char)0;
    }
}
