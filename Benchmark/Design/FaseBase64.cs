// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace FastBase64Lib;

#pragma warning disable SA1117
#pragma warning disable SA1519 // Braces should not be omitted from multi-line child statement

public static unsafe class FastBase64
{
    // ------------------------------------------------------------------
    // 長さ計算
    // ------------------------------------------------------------------

    /// <summary>入力 <paramref name="byteCount"/> バイトをエンコードした後の文字数(パディング込み・厳密値)。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int byteCount)
    {
        if (byteCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount));
        }

        long len = ((long)byteCount + 2) / 3 * 4;
        if (len > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(byteCount), "Encoded length exceeds Int32.MaxValue.");
        }

        return (int)len;
    }

    /// <summary>エンコード列の長さ <paramref name="encodedLength"/> からデコード結果の最大バイト数(上限)を返す。
    /// パディングの有無に関わらず安全なバッファサイズとして使える。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetMaxDecodedLength(int encodedLength)
    {
        if (encodedLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedLength));
        }

        return (int)((long)encodedLength * 3 / 4);
    }

    /// <summary>実際の入力を見て(末尾の '=' を数えて)デコード結果の厳密なバイト数を返す。長さが不正なら FormatException。</summary>
    public static int GetDecodedLength(ReadOnlySpan<byte> utf8)
    {
        int len = TrimPadding(utf8, out _);
        return DecodedLengthFromTrimmed(len);
    }

    /// <inheritdoc cref="GetDecodedLength(ReadOnlySpan{byte})"/>
    public static int GetDecodedLength(ReadOnlySpan<char> chars)
    {
        int len = TrimPadding(chars, out _);
        return DecodedLengthFromTrimmed(len);
    }

    // ------------------------------------------------------------------
    // エンコード (public API)
    // ------------------------------------------------------------------

    /// <summary>UTF-8(ASCII) バイト列へエンコード。書き込んだバイト数を返す。</summary>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<byte> utf8Destination)
    {
        int encodedLength = GetEncodedLength(bytes.Length);
        if (utf8Destination.Length < encodedLength)
        {
            throw new ArgumentException("Destination is too small.", nameof(utf8Destination));
        }

        if (bytes.IsEmpty)
        {
            return 0;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        fixed (byte* dest = &MemoryMarshal.GetReference(utf8Destination))
        {
            EncodeBytesCore(src, bytes.Length, dest);
        }
        return encodedLength;
    }

    /// <summary>UTF-16 文字列 (Span&lt;char&gt;) へエンコード。書き込んだ文字数を返す。</summary>
    public static int Encode(ReadOnlySpan<byte> bytes, Span<char> charsDestination)
    {
        int encodedLength = GetEncodedLength(bytes.Length);
        if (charsDestination.Length < encodedLength)
        {
            throw new ArgumentException("Destination is too small.", nameof(charsDestination));
        }

        if (bytes.IsEmpty)
        {
            return 0;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        fixed (char* dest = &MemoryMarshal.GetReference(charsDestination))
        {
            EncodeCharsCore(src, bytes.Length, dest);
        }
        return encodedLength;
    }

    /// <summary>string へエンコード。</summary>
    public static string EncodeToString(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return string.Empty;
        }

        int encodedLength = GetEncodedLength(bytes.Length);

        // 新規確保した文字列を fixed で直接書き込む (string.Create と同等の定石。
        // 確保直後で他から参照されていないため安全)。
        string result = new string('\0', encodedLength);
        fixed (char* dest = result)
        fixed (byte* src = &MemoryMarshal.GetReference(bytes))
        {
            EncodeCharsCore(src, bytes.Length, dest);
        }

        return result;
    }

    // ------------------------------------------------------------------
    // デコード (public API)
    // ------------------------------------------------------------------

    /// <summary>UTF-8(ASCII) バイト列からデコード。不正な入力・バッファ不足なら false。</summary>
    public static bool TryDecode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination, out int bytesWritten)
    {
        bytesWritten = 0;
        int len = TrimPadding(utf8, out bool ok);
        if (!ok)
        {
            return false;
        }

        int required = DecodedLengthFromTrimmedNoThrow(len);
        if (required < 0 || bytesDestination.Length < required)
        {
            return false;
        }

        if (len == 0)
        {
            return true;
        }

        fixed (byte* src = &MemoryMarshal.GetReference(utf8))
        fixed (byte* dest = &MemoryMarshal.GetReference(bytesDestination))
        {
            if (!DecodeFromUtf8Core(src, len, dest, dest + bytesDestination.Length))
            {
                return false;
            }
        }
        bytesWritten = required;
        return true;
    }

    /// <summary>UTF-16 文字列 (ReadOnlySpan&lt;char&gt;) からデコード。不正な入力・バッファ不足なら false。</summary>
    public static bool TryDecode(ReadOnlySpan<char> chars, Span<byte> bytesDestination, out int bytesWritten)
    {
        bytesWritten = 0;
        int len = TrimPadding(chars, out bool ok);
        if (!ok)
        {
            return false;
        }

        int required = DecodedLengthFromTrimmedNoThrow(len);
        if (required < 0 || bytesDestination.Length < required)
        {
            return false;
        }

        if (len == 0)
        {
            return true;
        }

        fixed (char* src = &MemoryMarshal.GetReference(chars))
        fixed (byte* dest = &MemoryMarshal.GetReference(bytesDestination))
        {
            if (!DecodeFromCharsCore(src, len, dest, dest + bytesDestination.Length))
            {
                return false;
            }
        }
        bytesWritten = required;
        return true;
    }

    /// <summary>UTF-8(ASCII) バイト列からデコード。書き込んだバイト数を返す。不正な入力なら FormatException。</summary>
    public static int Decode(ReadOnlySpan<byte> utf8, Span<byte> bytesDestination)
    {
        if (!TryDecode(utf8, bytesDestination, out int written))
        {
            ThrowInvalidBase64(bytesDestination.Length, utf8.Length);
        }

        return written;
    }

    /// <summary>UTF-16 文字列からデコード。書き込んだバイト数を返す。不正な入力なら FormatException。</summary>
    public static int Decode(ReadOnlySpan<char> chars, Span<byte> bytesDestination)
    {
        if (!TryDecode(chars, bytesDestination, out int written))
        {
            ThrowInvalidBase64(bytesDestination.Length, chars.Length);
        }

        return written;
    }

    /// <summary>string からデコードして新しい byte[] を返す。不正な入力なら FormatException。</summary>
    public static byte[] Decode(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        ReadOnlySpan<char> chars = base64;
        int required = GetDecodedLength(chars); // 長さが不正ならここで FormatException
        if (required == 0)
        {
            return Array.Empty<byte>();
        }

        byte[] result = new byte[required];
        if (!TryDecode(chars, result, out _))
        {
            throw new FormatException("The input is not a valid Base64 string.");
        }

        return result;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInvalidBase64(int destLength, int srcLength)
    {
        if (destLength < GetMaxDecodedLength(srcLength))
        {
            throw new ArgumentException("Destination may be too small.", "bytesDestination");
        }

        throw new FormatException("The input is not a valid Base64 sequence.");
    }

    // ------------------------------------------------------------------
    // 長さ・パディング ヘルパ
    // ------------------------------------------------------------------

    // 末尾の '='(最大 2 個)を除いた長さを返す。パディングの付き方が不正なら ok = false。
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int TrimPadding(ReadOnlySpan<byte> s, out bool ok)
    {
        int len = s.Length;
        int trimmed = len;
        if (trimmed > 0 && s[trimmed - 1] == (byte)'=')
        {
            trimmed--;
            if (trimmed > 0 && s[trimmed - 1] == (byte)'=')
            {
                trimmed--;
            }
        }
        // パディング付きの場合、全体長は 4 の倍数でなければならない
        ok = trimmed == len || (len & 3) == 0;
        return trimmed;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int TrimPadding(ReadOnlySpan<char> s, out bool ok)
    {
        int len = s.Length;
        int trimmed = len;
        if (trimmed > 0 && s[trimmed - 1] == '=')
        {
            trimmed--;
            if (trimmed > 0 && s[trimmed - 1] == '=')
            {
                trimmed--;
            }
        }

        ok = trimmed == len || (len & 3) == 0;
        return trimmed;
    }

    // パディング除去後の長さ → デコード結果の厳密なバイト数。長さ %4 == 1 は不正 (-1)。
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DecodedLengthFromTrimmedNoThrow(int trimmedLength)
    {
        int rem = trimmedLength & 3;
        if (rem == 1)
        {
            return -1;
        }

        return ((trimmedLength >> 2) * 3) + (rem == 0 ? 0 : rem - 1);
    }

    private static int DecodedLengthFromTrimmed(int trimmedLength)
    {
        int r = DecodedLengthFromTrimmedNoThrow(trimmedLength);
        if (r < 0)
        {
            throw new FormatException("Invalid Base64 length.");
        }

        return r;
    }

    // ------------------------------------------------------------------
    // 変換テーブル
    // ------------------------------------------------------------------

    private static ReadOnlySpan<byte> EncodingMap =>
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8;

    // ASCII → 6bit 値。不正な文字は -1。(RVA 静的データとして埋め込まれ、割り当ては発生しない)
    private static ReadOnlySpan<sbyte> DecodingMap => new sbyte[256]
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //   0- 15
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //  16- 31
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, //  32- 47  '+' '/'
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, //  48- 63  '0'-'9'
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, //  64- 79  'A'-'O'
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, //  80- 95  'P'-'Z'
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, //  96-111  'a'-'o'
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112-127  'p'-'z'
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    // ------------------------------------------------------------------
    // エンコード コア: SIMD 共通変換
    //
    //   入力ベクトルの各 32bit レーンに [b1, b0, b2, b1] (LE) の並びで
    //   3 バイトを置き、AND/乗算シフトで 4 つの 6bit インデックスへ分解、
    //   飽和減算 + pshufb LUT で ASCII に変換する (Muła の手法)。
    // ------------------------------------------------------------------

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<sbyte> EncodeVector256(Vector256<sbyte> str)
    {
        // 各レーンへ 3 バイトを [b1,b0,b2,b1] で配置するシャッフル
        Vector256<sbyte> shuffleVec = Vector256.Create(
             5, 4, 6, 5, 8, 7, 9, 8, 11, 10, 12, 11, 14, 13, 15, 14,
             1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        Vector256<sbyte> maskAC = Vector256.Create(0x0FC0FC00).AsSByte();
        Vector256<sbyte> maskBB = Vector256.Create(0x003F03F0).AsSByte();
        Vector256<ushort> shiftAC = Vector256.Create(0x04000040).AsUInt16();
        Vector256<short> shiftBB = Vector256.Create(0x01000010).AsInt16();

        // 6bit 値 → ASCII 差分 LUT
        Vector256<sbyte> lut = Vector256.Create(
            65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0,
            65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0);
        Vector256<sbyte> const51 = Vector256.Create((sbyte)51);
        Vector256<sbyte> const25 = Vector256.Create((sbyte)25);

        str = Avx2.Shuffle(str, shuffleVec);

        Vector256<sbyte> t0 = Avx2.And(str, maskAC);
        Vector256<sbyte> t2 = Avx2.And(str, maskBB);
        Vector256<ushort> t1 = Avx2.MultiplyHigh(t0.AsUInt16(), shiftAC);
        Vector256<short> t3 = Avx2.MultiplyLow(t2.AsInt16(), shiftBB);
        str = Avx2.Or(t1.AsSByte(), t3.AsSByte()); // 各バイト = 6bit インデックス (0..63)

        // 変換: index<=25 → +'A'、26..51 → +('a'-26)、52..61 → +('0'-52)、62 → '+'、63 → '/'
        Vector256<byte> indices = Avx2.SubtractSaturate(str.AsByte(), const51.AsByte());
        Vector256<sbyte> mask = Avx2.CompareGreaterThan(str, const25);
        Vector256<sbyte> lutIdx = Avx2.Subtract(indices.AsSByte(), mask);
        return Avx2.Add(str, Avx2.Shuffle(lut, lutIdx));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<sbyte> EncodeVector128(Vector128<sbyte> str)
    {
        Vector128<sbyte> shuffleVec = Vector128.Create(
            (sbyte)1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10);

        Vector128<sbyte> maskAC = Vector128.Create(0x0FC0FC00).AsSByte();
        Vector128<sbyte> maskBB = Vector128.Create(0x003F03F0).AsSByte();
        Vector128<ushort> shiftAC = Vector128.Create(0x04000040).AsUInt16();
        Vector128<short> shiftBB = Vector128.Create(0x01000010).AsInt16();

        Vector128<sbyte> lut = Vector128.Create(
            (sbyte)65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0);
        Vector128<sbyte> const51 = Vector128.Create((sbyte)51);
        Vector128<sbyte> const25 = Vector128.Create((sbyte)25);

        str = Ssse3.Shuffle(str, shuffleVec);

        Vector128<sbyte> t0 = Sse2.And(str, maskAC);
        Vector128<sbyte> t2 = Sse2.And(str, maskBB);
        Vector128<ushort> t1 = Sse2.MultiplyHigh(t0.AsUInt16(), shiftAC);
        Vector128<short> t3 = Sse2.MultiplyLow(t2.AsInt16(), shiftBB);
        str = Sse2.Or(t1.AsSByte(), t3.AsSByte());

        Vector128<byte> indices = Sse2.SubtractSaturate(str.AsByte(), const51.AsByte());
        Vector128<sbyte> mask = Sse2.CompareGreaterThan(str, const25);
        Vector128<sbyte> lutIdx = Sse2.Subtract(indices.AsSByte(), mask);
        return Sse2.Add(str, Ssse3.Shuffle(lut, lutIdx));
    }

    // ------------------------------------------------------------------
    // エンコード コア: bytes → UTF-8 bytes
    // ------------------------------------------------------------------

    private static void EncodeBytesCore(byte* srcStart, int srcLength, byte* destStart)
    {
        byte* src = srcStart;
        byte* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 24 バイト → 32 文字 / ループ ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;

            // 初回は src-4 を読めないため、src から 32B ロードして 4B 右論理シフト相当の
            // レーン移動 (permutevar8x32) で位置合わせする
            Vector256<int> permute = Vector256.Create(0, 0, 1, 2, 3, 4, 5, 6);
            Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
            str = Avx2.PermuteVar8x32(str.AsInt32(), permute).AsSByte();

            while (true)
            {
                Avx.Store((sbyte*)dest, EncodeVector256(str));
                src += 24;
                dest += 32;
                if (src > srcMax)
                {
                    break;
                }
                // 2 回目以降: 下位レーンが 4B 分オーバーラップするよう src-4 からロード
                str = Avx.LoadVector256(src - 4).AsSByte();
            }
        }

        // ---- SSSE3: 12 バイト → 16 文字 / ループ ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            do
            {
                Vector128<sbyte> str = Sse2.LoadVector128(src).AsSByte();
                Sse2.Store((sbyte*)dest, EncodeVector128(str));
                src += 12;
                dest += 16;
            } while (src <= srcMax);
        }

        // ---- スカラー ----
        ref byte map = ref MemoryMarshal.GetReference(EncodingMap);
        while (srcEnd - src >= 3)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8 | src[2]);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = Unsafe.Add(ref map, (nint)(t & 0x3F));
            src += 3;
            dest += 4;
        }

        long remaining = srcEnd - src; // 0, 1, 2
        if (remaining == 1)
        {
            uint t = (uint)(src[0] << 16);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (byte)'=';
            dest[3] = (byte)'=';
        }
        else if (remaining == 2)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8);
            dest[0] = Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = (byte)'=';
        }
    }

    // ------------------------------------------------------------------
    // エンコード コア: bytes → UTF-16 chars
    //   (ASCII ベクトルを vpmovzxbw / punpcklbw でゼロ拡張して直接ストア)
    // ------------------------------------------------------------------

    private static void EncodeCharsCore(byte* srcStart, int srcLength, char* destStart)
    {
        byte* src = srcStart;
        char* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 24 バイト → 32 文字 (64 バイトストア) / ループ ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;

            Vector256<int> permute = Vector256.Create(0, 0, 1, 2, 3, 4, 5, 6);
            Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
            str = Avx2.PermuteVar8x32(str.AsInt32(), permute).AsSByte();

            while (true)
            {
                Vector256<sbyte> ascii = EncodeVector256(str);
                Avx.Store((short*)dest, Avx2.ConvertToVector256Int16(ascii.GetLower().AsByte()));
                Avx.Store((short*)(dest + 16), Avx2.ConvertToVector256Int16(ascii.GetUpper().AsByte()));
                src += 24;
                dest += 32;
                if (src > srcMax)
                {
                    break;
                }

                str = Avx.LoadVector256(src - 4).AsSByte();
            }
        }

        // ---- SSSE3: 12 バイト → 16 文字 / ループ ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            Vector128<byte> zero = Vector128<byte>.Zero;
            do
            {
                Vector128<byte> ascii = EncodeVector128(Sse2.LoadVector128(src).AsSByte()).AsByte();
                Sse2.Store((byte*)dest, Sse2.UnpackLow(ascii, zero));
                Sse2.Store((byte*)(dest + 8), Sse2.UnpackHigh(ascii, zero));
                src += 12;
                dest += 16;
            } while (src <= srcMax);
        }

        // ---- スカラー ----
        ref byte map = ref MemoryMarshal.GetReference(EncodingMap);
        while (srcEnd - src >= 3)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8 | src[2]);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (char)Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = (char)Unsafe.Add(ref map, (nint)(t & 0x3F));
            src += 3;
            dest += 4;
        }

        long remaining = srcEnd - src;
        if (remaining == 1)
        {
            uint t = (uint)(src[0] << 16);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = '=';
            dest[3] = '=';
        }
        else if (remaining == 2)
        {
            uint t = (uint)(src[0] << 16 | src[1] << 8);
            dest[0] = (char)Unsafe.Add(ref map, (nint)(t >> 18));
            dest[1] = (char)Unsafe.Add(ref map, (nint)((t >> 12) & 0x3F));
            dest[2] = (char)Unsafe.Add(ref map, (nint)((t >> 6) & 0x3F));
            dest[3] = '=';
        }
    }

    // ------------------------------------------------------------------
    // デコード コア: SIMD 共通変換
    //
    //   上位/下位ニブルの pshufb LUT でビットマスクを引き、AND 結果が
    //   非ゼロなら不正文字 (ptest で一括検証)。有効文字は差分 LUT で
    //   6bit 値へ変換し、pmaddubsw + pmaddwd + pshufb で 3 バイトに詰める。
    // ------------------------------------------------------------------

    /// <summary>32 文字 → 24 バイト。不正文字を含む場合 false (結果は未定義)。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool DecodeVector256(Vector256<sbyte> str, out Vector256<sbyte> result)
    {
        Vector256<sbyte> lutHi = Vector256.Create(
            0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10).AsSByte();
        Vector256<sbyte> lutLo = Vector256.Create(
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A,
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A).AsSByte();
        Vector256<sbyte> lutShift = Vector256.Create(
            (sbyte)0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
        Vector256<sbyte> mask2F = Vector256.Create((sbyte)0x2F);
        Vector256<sbyte> mergeConst0 = Vector256.Create(0x01400140).AsSByte();
        Vector256<short> mergeConst1 = Vector256.Create(0x00011000).AsInt16();
        Vector256<sbyte> packBytesInLaneMask = Vector256.Create(
            (sbyte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);
        Vector256<int> packLanesControl = Vector256.Create(0, 1, 2, 4, 5, 6, -1, -1);

        Vector256<sbyte> hiNibbles = Avx2.And(Avx2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask2F);
        Vector256<sbyte> loNibbles = Avx2.And(str, mask2F);
        Vector256<sbyte> hi = Avx2.Shuffle(lutHi, hiNibbles);
        Vector256<sbyte> lo = Avx2.Shuffle(lutLo, loNibbles);

        if (!Avx.TestZ(lo, hi))
        {
            result = default;
            return false; // 不正文字あり
        }

        Vector256<sbyte> eq2F = Avx2.CompareEqual(str, mask2F);
        Vector256<sbyte> shift = Avx2.Shuffle(lutShift, Avx2.Add(eq2F, hiNibbles));
        str = Avx2.Add(str, shift); // 各バイト = 6bit 値

        // (a<<6|b), (c<<6|d) → (a<<18|b<<12|c<<6|d) → 下位 3 バイトを詰める
        Vector256<short> mergeAbBc = Avx2.MultiplyAddAdjacent(str.AsByte(), mergeConst0);
        Vector256<int> merged = Avx2.MultiplyAddAdjacent(mergeAbBc, mergeConst1);
        Vector256<sbyte> packed = Avx2.Shuffle(merged.AsSByte(), packBytesInLaneMask);
        result = Avx2.PermuteVar8x32(packed.AsInt32(), packLanesControl).AsSByte();
        return true;
    }

    /// <summary>16 文字 → 12 バイト。不正文字を含む場合 false。</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool DecodeVector128(Vector128<sbyte> str, out Vector128<sbyte> result)
    {
        Vector128<sbyte> lutHi = Vector128.Create(
            0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10).AsSByte();
        Vector128<sbyte> lutLo = Vector128.Create(
            0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A).AsSByte();
        Vector128<sbyte> lutShift = Vector128.Create(
            (sbyte)0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
        Vector128<sbyte> mask2F = Vector128.Create((sbyte)0x2F);
        Vector128<sbyte> mergeConst0 = Vector128.Create(0x01400140).AsSByte();
        Vector128<short> mergeConst1 = Vector128.Create(0x00011000).AsInt16();
        Vector128<sbyte> packBytesMask = Vector128.Create(
            (sbyte)2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);

        Vector128<sbyte> hiNibbles = Sse2.And(Sse2.ShiftRightLogical(str.AsInt32(), 4).AsSByte(), mask2F);
        Vector128<sbyte> loNibbles = Sse2.And(str, mask2F);
        Vector128<sbyte> hi = Ssse3.Shuffle(lutHi, hiNibbles);
        Vector128<sbyte> lo = Ssse3.Shuffle(lutLo, loNibbles);

        // 検証: SSE4.1 の ptest があれば 1 命令、なければ SSE2 の pmovmskb で代替
        if (Sse41.IsSupported)
        {
            if (!Sse41.TestZ(lo, hi))
            {
                result = default;
                return false;
            }
        }
        else
        {
            Vector128<sbyte> and = Sse2.And(lo, hi);
            if (Sse2.MoveMask(Sse2.CompareEqual(and, Vector128<sbyte>.Zero)) != 0xFFFF)
            {
                result = default;
                return false;
            }
        }

        Vector128<sbyte> eq2F = Sse2.CompareEqual(str, mask2F);
        Vector128<sbyte> shift = Ssse3.Shuffle(lutShift, Sse2.Add(eq2F, hiNibbles));
        str = Sse2.Add(str, shift);

        Vector128<short> mergeAbBc = Ssse3.MultiplyAddAdjacent(str.AsByte(), mergeConst0);
        Vector128<int> merged = Sse2.MultiplyAddAdjacent(mergeAbBc, mergeConst1);
        result = Ssse3.Shuffle(merged.AsSByte(), packBytesMask);
        return true;
    }

    // ------------------------------------------------------------------
    // デコード コア: UTF-8 bytes → bytes
    //   srcLength はパディング除去後の長さ。destEnd はバッファ終端
    //   (SIMD ストアのはみ出し保護に使用)。
    // ------------------------------------------------------------------

    private static bool DecodeFromUtf8Core(byte* srcStart, int srcLength, byte* destStart, byte* destEnd)
    {
        byte* src = srcStart;
        byte* dest = destStart;
        byte* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 32 文字 → 24 バイト / ループ (ストアは 32B、有効 24B) ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            byte* srcMax = srcEnd - 32;
            while (src <= srcMax && dest + 32 <= destEnd)
            {
                Vector256<sbyte> str = Avx.LoadVector256(src).AsSByte();
                if (!DecodeVector256(str, out Vector256<sbyte> decoded))
                {
                    break; // 不正文字はスカラーで正確に検出させる
                }

                Avx.Store((sbyte*)dest, decoded);
                src += 32;
                dest += 24;
            }
        }

        // ---- SSSE3: 16 文字 → 12 バイト / ループ (ストアは 16B、有効 12B) ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            byte* srcMax = srcEnd - 16;
            while (src <= srcMax && dest + 16 <= destEnd)
            {
                Vector128<sbyte> str = Sse2.LoadVector128(src).AsSByte();
                if (!DecodeVector128(str, out Vector128<sbyte> decoded))
                {
                    break;
                }

                Sse2.Store((sbyte*)dest, decoded);
                src += 16;
                dest += 12;
            }
        }

        // ---- スカラー: 4 文字 → 3 バイト ----
        ref sbyte map = ref MemoryMarshal.GetReference(DecodingMap);
        while (srcEnd - src >= 4)
        {
            int i0 = Unsafe.Add(ref map, (nint)src[0]);
            int i1 = Unsafe.Add(ref map, (nint)src[1]);
            int i2 = Unsafe.Add(ref map, (nint)src[2]);
            int i3 = Unsafe.Add(ref map, (nint)src[3]);
            if ((i0 | i1 | i2 | i3) < 0)
            {
                return false;
            }

            uint t = (uint)(i0 << 18 | i1 << 12 | i2 << 6 | i3);
            dest[0] = (byte)(t >> 16);
            dest[1] = (byte)(t >> 8);
            dest[2] = (byte)t;
            src += 4;
            dest += 3;
        }

        // ---- 端数 (0, 2, 3 文字) ----
        long rem = srcEnd - src;
        if (rem == 2)
        {
            int i0 = Unsafe.Add(ref map, (nint)src[0]);
            int i1 = Unsafe.Add(ref map, (nint)src[1]);
            if ((i0 | i1) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
        }
        else if (rem == 3)
        {
            int i0 = Unsafe.Add(ref map, (nint)src[0]);
            int i1 = Unsafe.Add(ref map, (nint)src[1]);
            int i2 = Unsafe.Add(ref map, (nint)src[2]);
            if ((i0 | i1 | i2) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
            dest[1] = (byte)(i1 << 4 | i2 >> 2);
        }
        return true;
    }

    // ------------------------------------------------------------------
    // デコード コア: UTF-16 chars → bytes
    //   packus (飽和ナロー) で char → byte に落とす。非 ASCII 文字は
    //   0 または 255 に飽和し、LUT 検証で必ず不正と判定される。
    // ------------------------------------------------------------------

    private static bool DecodeFromCharsCore(char* srcStart, int srcLength, byte* destStart, byte* destEnd)
    {
        char* src = srcStart;
        byte* dest = destStart;
        char* srcEnd = srcStart + (uint)srcLength;

        // ---- AVX2: 32 文字 (64B ロード ×2) → 24 バイト / ループ ----
        if (Avx2.IsSupported && srcLength >= 32)
        {
            char* srcMax = srcEnd - 32;
            while (src <= srcMax && dest + 32 <= destEnd)
            {
                Vector256<short> c0 = Avx.LoadVector256((short*)src);
                Vector256<short> c1 = Avx.LoadVector256((short*)(src + 16));
                Vector256<byte> packed = Avx2.PackUnsignedSaturate(c0, c1);
                // packus はレーン内で詰めるため 64bit 単位で並べ直す
                Vector256<sbyte> str = Avx2.Permute4x64(packed.AsInt64(), 0b_11_01_10_00).AsSByte();
                if (!DecodeVector256(str, out Vector256<sbyte> decoded))
                {
                    break;
                }

                Avx.Store((sbyte*)dest, decoded);
                src += 32;
                dest += 24;
            }
        }

        // ---- SSSE3: 16 文字 → 12 バイト / ループ ----
        if (Ssse3.IsSupported && srcEnd - src >= 16)
        {
            char* srcMax = srcEnd - 16;
            while (src <= srcMax && dest + 16 <= destEnd)
            {
                Vector128<short> c0 = Sse2.LoadVector128((short*)src);
                Vector128<short> c1 = Sse2.LoadVector128((short*)(src + 8));
                Vector128<sbyte> str = Sse2.PackUnsignedSaturate(c0, c1).AsSByte();
                if (!DecodeVector128(str, out Vector128<sbyte> decoded))
                {
                    break;
                }

                Sse2.Store((sbyte*)dest, decoded);
                src += 16;
                dest += 12;
            }
        }

        // ---- スカラー ----
        ref sbyte map = ref MemoryMarshal.GetReference(DecodingMap);
        while (srcEnd - src >= 4)
        {
            uint c0 = src[0], c1 = src[1], c2 = src[2], c3 = src[3];
            if ((c0 | c1 | c2 | c3) > 0xFF)
            {
                return false;
            }

            int i0 = Unsafe.Add(ref map, (nint)c0);
            int i1 = Unsafe.Add(ref map, (nint)c1);
            int i2 = Unsafe.Add(ref map, (nint)c2);
            int i3 = Unsafe.Add(ref map, (nint)c3);
            if ((i0 | i1 | i2 | i3) < 0)
            {
                return false;
            }

            uint t = (uint)(i0 << 18 | i1 << 12 | i2 << 6 | i3);
            dest[0] = (byte)(t >> 16);
            dest[1] = (byte)(t >> 8);
            dest[2] = (byte)t;
            src += 4;
            dest += 3;
        }

        long rem = srcEnd - src;
        if (rem == 2)
        {
            uint c0 = src[0], c1 = src[1];
            if ((c0 | c1) > 0xFF)
            {
                return false;
            }

            int i0 = Unsafe.Add(ref map, (nint)c0);
            int i1 = Unsafe.Add(ref map, (nint)c1);
            if ((i0 | i1) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
        }
        else if (rem == 3)
        {
            uint c0 = src[0], c1 = src[1], c2 = src[2];
            if ((c0 | c1 | c2) > 0xFF)
            {
                return false;
            }

            int i0 = Unsafe.Add(ref map, (nint)c0);
            int i1 = Unsafe.Add(ref map, (nint)c1);
            int i2 = Unsafe.Add(ref map, (nint)c2);
            if ((i0 | i1 | i2) < 0)
            {
                return false;
            }

            dest[0] = (byte)(i0 << 2 | i1 >> 4);
            dest[1] = (byte)(i1 << 4 | i2 >> 2);
        }
        return true;
    }
}
