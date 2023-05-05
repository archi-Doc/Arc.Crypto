// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

internal class Base32SortTable : IBaseConverter
{
    private static readonly char[] Utf16EncodeTable =
    {
        '2', '3', '4', '5', '6', '7',
        'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z',
    };

    private static readonly byte[] Utf8EncodeTable =
    {
        (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
        (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F',
        (byte)'G', (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L',
        (byte)'M', (byte)'N', (byte)'O', (byte)'P', (byte)'Q', (byte)'R',
        (byte)'S', (byte)'T', (byte)'U', (byte)'V', (byte)'W', (byte)'X',
        (byte)'Y', (byte)'Z',
    };

    public unsafe string FromByteArrayToString(ReadOnlySpan<byte> bytes)
    {
        var length = Base32Sort.GetEncodedLength(bytes.Length);
        char[]? pooledName = null;

        Span<char> span = length <= 1024 ?
            stackalloc char[length] :
            (pooledName = ArrayPool<char>.Shared.Rent(length));

        fixed (byte* data = &MemoryMarshal.GetReference(bytes))
        {
            fixed (char* utf = &MemoryMarshal.GetReference(span))
            {
                this.EncodeUtf16Core(data, utf, bytes.Length, Utf16EncodeTable);
            }
        }

        var result = new string(span);

        if (pooledName != null)
        {
            ArrayPool<char>.Shared.Return(pooledName);
        }

        return result;
    }

    public unsafe byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
    {
        var length = Base32Sort.GetEncodedLength(bytes.Length);
        var utf8 = new byte[length];
        var span = utf8.AsSpan();

        fixed (byte* data = &MemoryMarshal.GetReference(bytes))
        {
            fixed (byte* b = &MemoryMarshal.GetReference(span))
            {
                this.EncodeUtf8Core(data, b, bytes.Length, Utf8EncodeTable);
            }
        }

        return utf8;
    }

    public byte[] FromStringToByteArray(ReadOnlySpan<char> base32)
    {
        nint byteCount = Base32Sort.GetDecodedLength(base32.Length);
        byte[] returnArray = new byte[byteCount];

        byte current = 0;
        var remaining = 8;
        nint mask;
        nint arrayIndex = 0;

        foreach (char c in base32)
        {
            nint v = Base32SortReference.CharToValue(c);
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

    public byte[]? FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
    {
        nint byteCount = Base32Sort.GetDecodedLength(utf8.Length);
        byte[] returnArray = new byte[byteCount];

        byte current = 0;
        var remaining = 8;
        nint mask;
        nint arrayIndex = 0;

        foreach (var c in utf8)
        {
            nint v = Base32SortReference.ByteToValue(c);
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

    private unsafe int EncodeUtf16Core(byte* bytes, char* chars, int length, char[] encodeTable)
    {
        var mod5 = length % 5;
        var n = length - mod5;
        var i = 0;
        var j = 0;
        fixed (char* table = &encodeTable[0])
        {
            long* lp = (long*)chars;
            for (i = 0; i < n; i += 5)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[((bytes[i + 1] & 0b00000001) << 4) | ((bytes[i + 2] & 0b11110000) >> 4)];
                chars[j + 4] = table[((bytes[i + 2] & 0b00001111) << 1) | ((bytes[i + 3] & 0b10000000) >> 7)];
                chars[j + 5] = table[(bytes[i + 3] & 0b01111100) >> 2];
                chars[j + 6] = table[((bytes[i + 3] & 0b00000011) << 3) | ((bytes[i + 4] & 0b11100000) >> 5)];
                chars[j + 7] = table[bytes[i + 4] & 0b00011111];
                j += 8;
            }

            i = n;
            if (mod5 == 4)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[((bytes[i + 1] & 0b00000001) << 4) | ((bytes[i + 2] & 0b11110000) >> 4)];
                chars[j + 4] = table[((bytes[i + 2] & 0b00001111) << 1) | ((bytes[i + 3] & 0b10000000) >> 7)];
                chars[j + 5] = table[(bytes[i + 3] & 0b01111100) >> 2];
                chars[j + 6] = table[(bytes[i + 3] & 0b00000011) << 3];
                j += 7;
            }
            else if (mod5 == 3)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[((bytes[i + 1] & 0b00000001) << 4) | ((bytes[i + 2] & 0b11110000) >> 4)];
                chars[j + 4] = table[(bytes[i + 2] & 0b00001111) << 1];
                j += 5;
            }
            else if (mod5 == 2)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[(bytes[i + 1] & 0b00000001) << 4];
                j += 4;
            }
            else if (mod5 == 1)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[(bytes[i] & 0b00000111) << 2];
                j += 2;
            }

            return j;
        }
    }

    private unsafe int EncodeUtf8Core(byte* bytes, byte* chars, int length, byte[] encodeTable)
    {
        var mod5 = length % 5;
        var n = length - mod5;
        var i = 0;
        var j = 0;
        fixed (byte* table = &encodeTable[0])
        {
            long* lp = (long*)chars;
            for (i = 0; i < n; i += 5)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[((bytes[i + 1] & 0b00000001) << 4) | ((bytes[i + 2] & 0b11110000) >> 4)];
                chars[j + 4] = table[((bytes[i + 2] & 0b00001111) << 1) | ((bytes[i + 3] & 0b10000000) >> 7)];
                chars[j + 5] = table[(bytes[i + 3] & 0b01111100) >> 2];
                chars[j + 6] = table[((bytes[i + 3] & 0b00000011) << 3) | ((bytes[i + 4] & 0b11100000) >> 5)];
                chars[j + 7] = table[bytes[i + 4] & 0b00011111];
                j += 8;
            }

            i = n;
            if (mod5 == 4)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[((bytes[i + 1] & 0b00000001) << 4) | ((bytes[i + 2] & 0b11110000) >> 4)];
                chars[j + 4] = table[((bytes[i + 2] & 0b00001111) << 1) | ((bytes[i + 3] & 0b10000000) >> 7)];
                chars[j + 5] = table[(bytes[i + 3] & 0b01111100) >> 2];
                chars[j + 6] = table[(bytes[i + 3] & 0b00000011) << 3];
                j += 7;
            }
            else if (mod5 == 3)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[((bytes[i + 1] & 0b00000001) << 4) | ((bytes[i + 2] & 0b11110000) >> 4)];
                chars[j + 4] = table[(bytes[i + 2] & 0b00001111) << 1];
                j += 5;
            }
            else if (mod5 == 2)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[((bytes[i] & 0b00000111) << 2) | ((bytes[i + 1] & 0b11000000) >> 6)];
                chars[j + 2] = table[(bytes[i + 1] & 0b00111110) >> 1];
                chars[j + 3] = table[(bytes[i + 1] & 0b00000001) << 4];
                j += 4;
            }
            else if (mod5 == 1)
            {
                chars[j] = table[(bytes[i] & 0b11111000) >> 3];
                chars[j + 1] = table[(bytes[i] & 0b00000111) << 2];
                j += 2;
            }

            return j;
        }
    }
}
