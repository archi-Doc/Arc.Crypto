// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Arc.Crypto;

internal class Base32SortTable : IBaseConverter
{
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
            else
            {
                DecodeTable[i] = byte.MaxValue;
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
                this.EncodeUtf16Core(data, utf, bytes.Length, Base32Sort.Utf16EncodeTable);
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
                this.EncodeUtf8Core(data, b, bytes.Length, Base32Sort.Utf8EncodeTable);
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
                if (!this.DecodeUtf16Core(inChars, outData, utf16.Length, DecodeTable))
                {
                    return Array.Empty<byte>();
                }
            }
        }

        return bytes;
    }

    public unsafe byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
    {
        nint length = Base32Sort.GetDecodedLength(utf8.Length);
        byte[] bytes = new byte[length];

        fixed (byte* inChars = &MemoryMarshal.GetReference(utf8))
        {
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes.AsSpan()))
            {
                if (!this.DecodeUtf8Core(inChars, outData, utf8.Length, DecodeTable))
                {
                    return Array.Empty<byte>();
                }
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

    private unsafe bool DecodeUtf16Core(char* inChars, byte* outData, int length, byte[] decodeTable)
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
                if (IsInvalid(i0, i1, i2, i3, i4, i5, i6, i7))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3, i4, i5, i6))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3, i4, i5))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3, i4))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3))
                {
                    return false;
                }

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
            }
            else if (remaining == 3)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                var i2 = table[inChars[i + 2] & 0xFF];
                if (IsInvalid(i0, i1, i2))
                {
                    return false;
                }

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
            else if (remaining == 2)
            {
                var i0 = table[inChars[i] & 0xFF];
                var i1 = table[inChars[i + 1] & 0xFF];
                if (IsInvalid(i0, i1))
                {
                    return false;
                }

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
        }

        return true;
    }

    private unsafe bool DecodeUtf8Core(byte* inChars, byte* outData, int length, byte[] decodeTable)
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
                if (IsInvalid(i0, i1, i2, i3, i4, i5, i6, i7))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3, i4, i5, i6))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3, i4, i5))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3, i4))
                {
                    return false;
                }

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
                if (IsInvalid(i0, i1, i2, i3))
                {
                    return false;
                }

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
                outData[j + 1] = (byte)(((i1 & 0b00000011) << 6) | (i2 << 1) | ((i3 & 0b00010000) >> 4));
            }
            else if (remaining == 3)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                var i2 = table[inChars[i + 2]];
                if (IsInvalid(i0, i1, i2))
                {
                    return false;
                }

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
            else if (remaining == 2)
            {
                var i0 = table[inChars[i]];
                var i1 = table[inChars[i + 1]];
                if (IsInvalid(i0, i1))
                {
                    return false;
                }

                outData[j] = (byte)((i0 << 3) | ((i1 & 0b00011100) >> 2));
            }
        }

        return true;
    }

#pragma warning disable CS0675
#pragma warning disable SA1204
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0)
        => (i0 & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1)
        => ((i0 | i1) & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1, byte i2)
        => ((i0 | i1 | i2) & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1, byte i2, byte i3)
        => ((i0 | i1 | i2 | i3) & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1, byte i2, byte i3, byte i4)
        => ((i0 | i1 | i2 | i3 | i4) & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1, byte i2, byte i3, byte i4, byte i5)
        => ((i0 | i1 | i2 | i3 | i4 | i5) & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1, byte i2, byte i3, byte i4, byte i5, byte i6)
        => ((i0 | i1 | i2 | i3 | i4 | i5 | i6) & 0b10000000) == 0b10000000;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsInvalid(byte i0, byte i1, byte i2, byte i3, byte i4, byte i5, byte i6, byte i7)
        => ((i0 | i1 | i2 | i3 | i4 | i5 | i6 | i7) & 0b10000000) == 0b10000000;

#pragma warning restore SA1204
#pragma warning restore CS0675
}
