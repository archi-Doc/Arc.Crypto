// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
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

    private static readonly byte[] DecodeTable;

    static Base32SortTable()
    {
        DecodeTable = new byte[byte.MaxValue];
        for (byte i = 0; i < DecodeTable.Length; i++)
        {
            var v = Base32SortReference.ByteToValue(i);
            if (v >= 0)
            {
                DecodeTable[i] = (byte)v;
            }
        }
    }

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

    public unsafe byte[] FromStringToByteArray(ReadOnlySpan<char> utf16)
    {
        nint length = Base32Sort.GetDecodedLength(utf16.Length);
        byte[] bytes = new byte[length];

        fixed (char* inChars = &MemoryMarshal.GetReference(utf16))
        {
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes.AsSpan()))
            {
                this.DecodeUtf16Core(inChars, outData, utf16.Length, DecodeTable);
            }
        }

        return bytes;
    }

    public unsafe byte[]? FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
    {
        nint length = Base32Sort.GetDecodedLength(utf8.Length);
        byte[] bytes = new byte[length];

        fixed (byte* inChars = &MemoryMarshal.GetReference(utf8))
        {
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes.AsSpan()))
            {
                this.DecodeUtf8Core(inChars, outData, utf8.Length, DecodeTable);
            }
        }

        return bytes;
    }

    private unsafe int EncodeUtf16Core(byte* bytes, char* chars, int length, char[] encodeTable)
    {
        var mod5 = length % 5;
        var n = length - mod5;
        var i = 0;
        var j = 0;
        fixed (char* table = &encodeTable[0])
        {
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

    private unsafe void DecodeUtf16Core(char* inChars, byte* outData, int length, byte[] decodeTable)
    {
        var n = length & ~7;
        var i = 0;
        var j = 0;
        fixed (byte* table = &decodeTable[0])
        {
            for (i = 0; i < n; i += 8)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];
                var i3 = table[inChars[i + 3] & 0xFF];
                var i4 = table[inChars[i + 4] & 0xFF];
                var i5 = table[inChars[i + 5] & 0xFF];
                var i6 = table[inChars[i + 6] & 0xFF];
                var i7 = table[inChars[i + 7] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
                outData[j + 3] = (byte)(((i4 & 0b00000001) << 7) | (i5 << 2) | ((i6 & 0b00011000) >> 3));
                outData[j + 4] = (byte)(((i6 & 0b00000111) << 5) | i7);

                j += 5;
            }

            var remaining = length - i;
            if (remaining == 7)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];
                var i3 = table[inChars[i + 3] & 0xFF];
                var i4 = table[inChars[i + 4] & 0xFF];
                var i5 = table[inChars[i + 5] & 0xFF];
                var i6 = table[inChars[i + 6] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
                outData[j + 3] = (byte)(((i4 & 0b00000001) << 7) | (i5 << 2) | ((i6 & 0b00011000) >> 3));
            }
            else if (remaining == 6)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];
                var i3 = table[inChars[i + 3] & 0xFF];
                var i4 = table[inChars[i + 4] & 0xFF];
                var i5 = table[inChars[i + 5] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
            }
            else if (remaining == 5)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];
                var i3 = table[inChars[i + 3] & 0xFF];
                var i4 = table[inChars[i + 4] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
            }
            else if (remaining == 4)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];
                var i3 = table[inChars[i + 3] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
            }
            else if (remaining == 3)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
            else if (remaining == 2)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
        }
    }

    private unsafe void DecodeUtf8Core(byte* inChars, byte* outData, int length, byte[] decodeTable)
    {
        var n = length & ~7;
        var i = 0;
        var j = 0;
        fixed (byte* table = &decodeTable[0])
        {
            for (i = 0; i < n; i += 8)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];
                var i3 = table[inChars[i + 3]];
                var i4 = table[inChars[i + 4]];
                var i5 = table[inChars[i + 5]];
                var i6 = table[inChars[i + 6]];
                var i7 = table[inChars[i + 7]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
                outData[j + 3] = (byte)(((i4 & 0b00000001) << 7) | (i5 << 2) | ((i6 & 0b00011000) >> 3));
                outData[j + 4] = (byte)(((i6 & 0b00000111) << 5) | i7);

                j += 5;
            }

            var remaining = length - i;
            if (remaining == 7)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];
                var i3 = table[inChars[i + 3]];
                var i4 = table[inChars[i + 4]];
                var i5 = table[inChars[i + 5]];
                var i6 = table[inChars[i + 6]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
                outData[j + 3] = (byte)(((i4 & 0b00000001) << 7) | (i5 << 2) | ((i6 & 0b00011000) >> 3));
            }
            else if (remaining == 6)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];
                var i3 = table[inChars[i + 3]];
                var i4 = table[inChars[i + 4]];
                var i5 = table[inChars[i + 5]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
            }
            else if (remaining == 5)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];
                var i3 = table[inChars[i + 3]];
                var i4 = table[inChars[i + 4]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
                outData[j + 2] = (byte)(((i3 & 0b00001111) << 4) | ((i4 & 0b00011110) >> 1));
            }
            else if (remaining == 4)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];
                var i3 = table[inChars[i + 3]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
            }
            else if (remaining == 3)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
            else if (remaining == 2)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
        }
    }
}
