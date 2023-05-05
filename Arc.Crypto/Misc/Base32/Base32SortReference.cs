// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

internal class Base32SortReference : IBaseConverter
{
    public Base32SortReference(char[] utf16EncodeTable, byte[] utf8EncodeTable, byte[] decodeTable)
    {
        this.utf16EncodeTable = utf16EncodeTable;
        this.utf8EncodeTable = utf8EncodeTable;
        this.decodeTable = decodeTable;
    }

    private char[] utf16EncodeTable;
    private byte[] utf8EncodeTable;
    private byte[] decodeTable;

    public unsafe string FromByteArrayToString(ReadOnlySpan<byte> bytes)
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
            span[index++] = this.ValueToChar(next);

            if (remaining < 4)
            {
                next = (byte)((b >> (3 - remaining)) & 31);
                span[index++] = this.ValueToChar(next);
                remaining += 5;
            }

            remaining -= 3;
            next = (byte)((b << remaining) & 31);
        }

        if (index != length)
        {
            span[index++] = this.ValueToChar(next);
        }

        var result = new string(span);

        if (pooledName != null)
        {
            ArrayPool<char>.Shared.Return(pooledName);
        }

        return result;
    }

    public byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
    {
        var length = Base32Sort.GetEncodedLength(bytes.Length);
        var utf8 = new byte[length];
        var span = utf8.AsSpan();

        byte next = 0;
        var remaining = 5;
        var index = 0;

        foreach (var b in bytes)
        {
            next = (byte)(next | (b >> (8 - remaining)));
            span[index++] = this.ValueToByte(next);

            if (remaining < 4)
            {
                next = (byte)((b >> (3 - remaining)) & 31);
                span[index++] = this.ValueToByte(next);
                remaining += 5;
            }

            remaining -= 3;
            next = (byte)((b << remaining) & 31);
        }

        if (index != length)
        {
            span[index++] = this.ValueToByte(next);
        }

        return utf8;
    }

    public byte[] FromStringToByteArray(ReadOnlySpan<char> utf16)
    {
        nint byteCount = Base32Sort.GetDecodedLength(utf16.Length);
        byte[] returnArray = new byte[byteCount];

        byte current = 0;
        var remaining = 8;
        nint mask;
        nint arrayIndex = 0;

        foreach (char c in utf16)
        {
            nint v = this.CharToValue(c);
            if (v >= byte.MaxValue)
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

    public byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
    {
        nint byteCount = Base32Sort.GetDecodedLength(utf8.Length);
        byte[] returnArray = new byte[byteCount];

        byte current = 0;
        var remaining = 8;
        nint mask;
        nint arrayIndex = 0;

        foreach (var c in utf8)
        {
            nint v = this.ByteToValue(c);
            if (v >= byte.MaxValue)
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal nint CharToValue(char c)
    {
        if (c > byte.MaxValue)
        {
            return -1;
        }
        else
        {
            return this.decodeTable[c];
        }

        /*var value = (nint)c;

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

        return -1;*/
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal nint ByteToValue(byte c)
    {
        if (c > byte.MaxValue)
        {
            return -1;
        }
        else
        {
            return this.decodeTable[c];
        }

        /*var value = (nint)c;

        if (value >= 50 && value <= 55)
        {// '2' 50 - '7' 55 -> 0-5
            return value - 50;
        }
        else if (value >= 65 && value <= 90)
        {// 'A' 65 0x41 - 'Z' 90 0x5A -> 6-31
            return value - 59;
        }
        else if (value >= 97 && value <= 122)
        {// 'a' 97 0x61 - 'z' 122 0x7A -> 6-31
            return value - 91;
        }

        return -1;*/
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private char ValueToChar(byte b)
    {
        return this.utf16EncodeTable[b];

        /*if (b < 6)
        {// 0-5 -> '2' 50 - '7' 55
            return (char)(b + 50);
        }
        else if (b < 32)
        {// 6-31 -> 'A' 65 0x41 - 'Z' 90 0x5A
            return (char)(b + 59);
        }

        return (char)0;*/
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private byte ValueToByte(byte b)
    {
        return this.utf8EncodeTable[b];

        /*if (b < 6)
        {// 0-5 -> '2' 50 - '7' 55
            return (byte)(b + 50);
        }
        else if (b < 32)
        {// 6-31 -> 'A' 65 0x41 - 'Z' 90 0x5A
            return (byte)(b + 59);
        }

        return 0;*/
    }
}
