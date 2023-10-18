// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

internal class Base32SortReference : IBase32Converter
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

    public bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<byte> destination, out int written)
    {
        var encodedLength = Base32Sort.GetEncodedLength(source.Length);
        if (destination.Length < encodedLength)
        {
            written = 0;
            return false;
        }

        this.ByteSpanToByteSpan(source, destination, encodedLength);
        written = encodedLength;
        return true;
    }

    public bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<char> destination, out int written)
    {
        var encodedLength = Base32Sort.GetEncodedLength(source.Length);
        if (destination.Length < encodedLength)
        {
            written = 0;
            return false;
        }

        this.ByteSpanToCharSpan(source, destination, encodedLength);
        written = encodedLength;
        return true;
    }

    public string FromByteArrayToString(ReadOnlySpan<byte> source)
    {
        var encodedLength = Base32Sort.GetEncodedLength(source.Length);
        char[]? pooledName = null;

        Span<char> destination = encodedLength <= 1024 ?
            stackalloc char[encodedLength] :
            (pooledName = ArrayPool<char>.Shared.Rent(encodedLength));

        this.ByteSpanToCharSpan(source, destination, encodedLength);
        var result = new string(destination);

        if (pooledName != null)
        {
            ArrayPool<char>.Shared.Return(pooledName);
        }

        return result;
    }

    public byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> source)
    {
        var encodedLength = Base32Sort.GetEncodedLength(source.Length);
        var destination = new byte[encodedLength];

        this.ByteSpanToByteSpan(source, destination, encodedLength);

        return destination;
    }

    public bool FromUtf8ToSpan(ReadOnlySpan<byte> base32, Span<byte> destination, out int written)
    {
        var decodedLength = Base32Sort.GetDecodedLength(base32.Length);
        if (destination.Length < decodedLength)
        {
            written = 0;
            return false;
        }

        if (!this.ByteToByte(base32, destination, decodedLength))
        {
            written = 0;
            return false;
        }

        written = decodedLength;
        return true;
    }

    public bool FromStringToSpan(ReadOnlySpan<char> base32, Span<byte> destination, out int written)
    {
        var decodedLength = Base32Sort.GetDecodedLength(base32.Length);
        if (destination.Length < decodedLength)
        {
            written = 0;
            return false;
        }

        if (!this.CharToByte(base32, destination, decodedLength))
        {
            written = 0;
            return false;
        }

        written = decodedLength;
        return true;
    }

    public byte[] FromStringToByteArray(ReadOnlySpan<char> base32)
    {
        var decodedLength = Base32Sort.GetDecodedLength(base32.Length);
        byte[] destination = new byte[decodedLength];

        if (!this.CharToByte(base32, destination, decodedLength))
        {
            return Array.Empty<byte>();
        }

        return destination;
    }

    public byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> base32)
    {
        var decodedLength = Base32Sort.GetDecodedLength(base32.Length);
        byte[] destination = new byte[decodedLength];

        if (!this.ByteToByte(base32, destination, decodedLength))
        {
            return Array.Empty<byte>();
        }

        return destination;
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

    private void ByteSpanToCharSpan(ReadOnlySpan<byte> source, Span<char> destination, int encodedLength)
    {
        byte next = 0;
        var remaining = 5;
        var index = 0;

        foreach (var b in source)
        {
            next = (byte)(next | (b >> (8 - remaining)));
            destination[index++] = this.ValueToChar(next);

            if (remaining < 4)
            {
                next = (byte)((b >> (3 - remaining)) & 31);
                destination[index++] = this.ValueToChar(next);
                remaining += 5;
            }

            remaining -= 3;
            next = (byte)((b << remaining) & 31);
        }

        if (index != encodedLength)
        {
            destination[index++] = this.ValueToChar(next);
        }
    }

    private void ByteSpanToByteSpan(ReadOnlySpan<byte> source, Span<byte> destination, int encodedLength)
    {
        byte next = 0;
        var remaining = 5;
        var index = 0;

        foreach (var b in source)
        {
            next = (byte)(next | (b >> (8 - remaining)));
            destination[index++] = this.ValueToByte(next);

            if (remaining < 4)
            {
                next = (byte)((b >> (3 - remaining)) & 31);
                destination[index++] = this.ValueToByte(next);
                remaining += 5;
            }

            remaining -= 3;
            next = (byte)((b << remaining) & 31);
        }

        if (index != encodedLength)
        {
            destination[index++] = this.ValueToByte(next);
        }
    }

    private bool CharToByte(ReadOnlySpan<char> base32, Span<byte> destination, int decodedLength)
    {
        byte current = 0;
        var remaining = 8;
        nint mask;
        var arrayIndex = 0;

        foreach (char c in base32)
        {
            nint v = this.CharToValue(c);
            if (v >= byte.MaxValue)
            {// Invalid character
                return false;
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
                destination[arrayIndex++] = current;
                current = (byte)(v << (3 + remaining));
                remaining += 3;
            }
        }

        if (arrayIndex != decodedLength)
        {
            destination[arrayIndex] = current;
        }

        return true;
    }

    private bool ByteToByte(ReadOnlySpan<byte> base32, Span<byte> destination, int decodedLength)
    {
        byte current = 0;
        var remaining = 8;
        nint mask;
        var arrayIndex = 0;

        foreach (var c in base32)
        {
            nint v = this.ByteToValue(c);
            if (v >= byte.MaxValue)
            {// Invalid character
                return false;
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
                destination[arrayIndex++] = current;
                current = (byte)(v << (3 + remaining));
                remaining += 3;
            }
        }

        if (arrayIndex != decodedLength)
        {
            destination[arrayIndex] = current;
        }

        return true;
    }
}
