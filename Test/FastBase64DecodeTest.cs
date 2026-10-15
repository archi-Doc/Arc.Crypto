// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Buffers.Text;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

/// <summary>
/// Decoder validation for <see cref="FastBase64"/> and <see cref="FastBase64Url"/>: canonical trailing bits,
/// invalid characters inside SIMD-sized blocks, non-ASCII UTF-16 input, whitespace, padding and destination errors.
/// </summary>
public class FastBase64DecodeTest
{
    private const string StandardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private const byte Marker = 0xA5;

    // UTF-16 values whose low byte is an alphabet character, or that saturate to 0x00/0xFF when narrowed.
    private static readonly char[] NonAsciiChars =
    [
        'Ā', 'İ', 'Ł', 'ī', 'ĭ', 'į', 'ş', 'š', '罁', '翿',
        '耀', '聁', '\uD800', '\uDFFF', 'Ａ', 'Ｋ', 'ａ', '￿',
    ];

    public static TheoryData<bool> Alphabets => new() { false, true, };

    // RFC 4648 section 3.5: a canonical encoding has zero pad bits, and decoders may reject other encodings.
    [Theory]
    [InlineData("AB==")]
    [InlineData("Zh==")]
    [InlineData("Zm9=")]
    [InlineData("AAB=")]
    [InlineData("Zm9vYh==")]
    [InlineData("Zm9vYmF=")]
    public void NonCanonicalTrailingBitsAreRejected(string padded)
    {
        foreach (var url in new[] { false, true })
        {
            AssertRejected(url, padded);
            AssertRejected(url, padded.TrimEnd('='));
        }
    }

    [Theory]
    [InlineData("AA==", new byte[] { 0x00 })]
    [InlineData("Zg==", new byte[] { 0x66 })]
    [InlineData("Zm8=", new byte[] { 0x66, 0x6F })]
    [InlineData("Zm9vYg==", new byte[] { 0x66, 0x6F, 0x6F, 0x62 })]
    public void CanonicalTrailingBitsAreAccepted(string padded, byte[] expected)
    {
        foreach (var url in new[] { false, true })
        {
            foreach (var text in new[] { padded, padded.TrimEnd('=') })
            {
                Decode(url, text).Is(expected);

                var destination = new byte[expected.Length];
                TryDecode(url, Encoding.ASCII.GetBytes(text), destination, out var written).IsTrue();
                written.Is(expected.Length);
                destination.Is(expected);

                destination = new byte[expected.Length];
                TryDecode(url, text.AsSpan(), destination, out written).IsTrue();
                written.Is(expected.Length);
                destination.Is(expected);
            }
        }
    }

    /// <summary>
    /// Every 2- and 3-character final quantum, with and without a prefix long enough for the SIMD loops, is accepted
    /// exactly when System.Buffers.Text.Base64 (padded input) or Base64Url (unpadded input) accepts it.
    /// </summary>
    /// <param name="url"><see langword="true"/> for <see cref="FastBase64Url"/>.</param>
    [Theory]
    [MemberData(nameof(Alphabets))]
    public void FinalQuantumMatchesBcl(bool url)
    {
        var alphabet = url ? UrlAlphabet : StandardAlphabet;
        var prefix = new string('A', 96);
        var destination = new byte[128];
        var expected = new byte[128];

        foreach (var head in new[] { string.Empty, prefix })
        {
            foreach (var first in new[] { 'Z', '0' })
            {
                for (var i = 0; i < 64; i++)
                {
                    for (var j = 0; j < 64; j++)
                    {
                        Check(head + alphabet[i] + alphabet[j]);
                        Check(head + first + alphabet[i] + alphabet[j]);
                    }
                }
            }
        }

        void Check(string unpadded)
        {
            var padded = unpadded.PadRight((unpadded.Length + 3) & ~3, '=');
            int expectedLength;
            OperationStatus status;
            if (url)
            {
                status = Base64Url.DecodeFromChars(unpadded, expected, out _, out expectedLength);
            }
            else
            {
                status = Base64.DecodeFromUtf8(Encoding.ASCII.GetBytes(padded), expected, out _, out expectedLength);
            }

            var valid = status == OperationStatus.Done;
            foreach (var input in new[] { unpadded, padded })
            {
                Assert.True(valid == TryDecode(url, input.AsSpan(), destination, out var written), input);
                if (valid)
                {
                    written.Is(expectedLength);
                    Assert.True(destination.AsSpan(0, written).SequenceEqual(expected.AsSpan(0, expectedLength)), input);
                }

                Assert.True(valid == TryDecode(url, Encoding.ASCII.GetBytes(input), destination, out written), input);
                if (valid)
                {
                    written.Is(expectedLength);
                    Assert.True(destination.AsSpan(0, written).SequenceEqual(expected.AsSpan(0, expectedLength)), input);
                }
            }
        }
    }

    /// <summary>
    /// Replaces each position of 32-, 64- and 96-character inputs (covering the SSSE3, AVX2 and scalar blocks) and of
    /// inputs with a 2- or 3-character tail by every byte value, through both input types.
    /// </summary>
    /// <param name="url"><see langword="true"/> for <see cref="FastBase64Url"/>.</param>
    [Theory]
    [MemberData(nameof(Alphabets))]
    public void EveryCharacterAtEveryPositionIsValidated(bool url)
    {
        var alphabet = url ? UrlAlphabet : StandardAlphabet;
        var random = new Random(url ? 64 : 46);
        foreach (var byteLength in new[] { 24, 48, 72, 73, 74, })
        {
            var data = new byte[byteLength];
            random.NextBytes(data);
            var standard = Convert.ToBase64String(data).TrimEnd('=');
            var original = url ? standard.Replace('+', '-').Replace('/', '_') : standard;
            var length = original.Length;
            var utf8 = Encoding.ASCII.GetBytes(original);
            var chars = original.ToCharArray();
            var destination = new byte[byteLength + 64];
            destination.AsSpan().Fill(Marker);

            for (var position = 0; position < length; position++)
            {
                for (var value = 0; value < 256; value++)
                {
                    var c = (char)value;
                    utf8[position] = (byte)value;
                    chars[position] = c;

                    var index = alphabet.IndexOf(c);
                    bool valid;
                    if (position < length - 1)
                    {
                        valid = index >= 0;
                    }
                    else if ((length & 3) == 0)
                    {
                        // A final '=' turns the last quantum into a padded 3-character one.
                        valid = index >= 0 || (c == '=' && (alphabet.IndexOf(chars[length - 2]) & 0x03) == 0);
                    }
                    else
                    {
                        // The unused low bits of the tail's last character must be zero.
                        valid = index >= 0 && (index & ((length & 3) == 2 ? 0x0F : 0x03)) == 0;
                    }

                    var resultUtf8 = TryDecode(url, utf8, destination, out var writtenUtf8);
                    var resultChars = TryDecode(url, chars, destination, out var writtenChars);
                    if (resultUtf8 != valid || resultChars != valid)
                    {
                        Assert.Fail($"Length {length}, position {position}, value 0x{value:X2}: expected {valid}, UTF-8 {resultUtf8}, UTF-16 {resultChars}.");
                    }

                    if (valid)
                    {
                        var text = new string(chars).Replace('-', '+').Replace('_', '/');
                        var expected = Convert.FromBase64String(text.PadRight((text.Length + 3) & ~3, '='));
                        writtenUtf8.Is(expected.Length);
                        writtenChars.Is(expected.Length);
                        Assert.True(destination.AsSpan(0, expected.Length).SequenceEqual(expected), $"Length {length}, position {position}, value 0x{value:X2}.");
                    }
                    else
                    {
                        writtenUtf8.Is(0);
                        writtenChars.Is(0);
                    }
                }

                utf8[position] = (byte)original[position];
                chars[position] = original[position];
            }

            // Neither successful nor failed decodes write past the decoded length.
            Assert.True(destination.AsSpan(byteLength).IndexOfAnyExcept(Marker) < 0, $"Length {length} wrote past the decoded length.");
        }
    }

    [Theory]
    [MemberData(nameof(Alphabets))]
    public void NonAsciiCharacterAtEveryPositionIsRejected(bool url)
    {
        var random = new Random(url ? 128 : 256);
        foreach (var byteLength in new[] { 24, 48, 72, 74, })
        {
            var data = new byte[byteLength];
            random.NextBytes(data);
            var encoded = url ? FastBase64Url.EncodeToString(data) : FastBase64.EncodeToString(data);
            var chars = encoded.ToCharArray();
            var destination = new byte[byteLength];

            for (var position = 0; position < chars.Length; position++)
            {
                foreach (var c in NonAsciiChars)
                {
                    chars[position] = c;
                    if (TryDecode(url, chars, destination, out var written) || written != 0)
                    {
                        Assert.Fail($"Length {chars.Length}, position {position}: U+{(int)c:X4} was accepted.");
                    }
                }

                chars[position] = encoded[position];
            }

            TryDecode(url, chars, destination, out _).IsTrue();
            destination.Is(data);
        }
    }

    // Each input has a valid length, so it is rejected by character validation rather than by the length check.
    [Theory]
    [InlineData("Zm 9")]
    [InlineData("Zm9v\r\nYmFy")]
    [InlineData("Zm9vYmFy\tZm9")]
    [InlineData("Zm9v Ym=")] // Reaches the 3-character tail.
    [InlineData("Zm9vYm\n")] // Reaches the 3-character tail.
    [InlineData("Zm9v\nA")] // Reaches the 2-character tail.
    public void WhitespaceIsRejected(string text)
    {
        AssertRejected(false, text);
        AssertRejected(true, text);
    }

    [Fact]
    public void LineBreakInsideSimdBlockIsRejected()
    {
        var data = new byte[114];
        new Random(114).NextBytes(data);
        var text = Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks);
        text.Length.Is(154); // 152 characters and a CRLF after the 76th; 154 % 4 == 2, so the length is valid.
        Convert.FromBase64String(text).Is(data); // The lenient BCL decoder skips the line break.

        AssertRejected(false, text);
        AssertRejected(true, text.Replace('+', '-').Replace('/', '_'));
    }

    [Theory]
    [InlineData("AA=")]
    [InlineData("A")]
    [InlineData("AAAAA")]
    [InlineData("####")]
    [InlineData("Zm9v#A")]
    [InlineData("Zm9vZm#")]
    [InlineData("Zm9vé")] // As UTF-8, 0xC3 0xA9 forms the 2-character tail.
    [InlineData("éé")]
    [InlineData("ŁŁŁŁ")] // Low byte 0x41 ('A').
    [InlineData("ａAAA")]
    [InlineData("Zm9vŁŁ")]
    [InlineData("Zm9vZmŁ")]
    [InlineData("Zm9v!A")]
    [InlineData("Zm9vZm!")]
    [InlineData("Zm9vZmİ")] // Low byte 0x30 ('0').
    [InlineData("Zm=v")]
    [InlineData("====")]
    [InlineData("A===")]
    public void InvalidInputIsRejected(string text)
    {
        AssertRejected(false, text);
        AssertRejected(true, text);
    }

    [Theory]
    [InlineData("-___", false)]
    [InlineData("+///", true)]
    public void OtherAlphabetIsRejected(string quantum, bool url)
    {
        AssertRejected(url, quantum);

        // The same quantum inside a SIMD block.
        var text = new string('A', 40) + quantum + new string('A', 52);
        AssertRejected(url, text);
    }

    [Theory]
    [InlineData("AA=")]
    [InlineData("AAA==")]
    [InlineData("Zm9vY===")]
    [InlineData("=")]
    [InlineData("==")]
    public void BadPaddingThrows(string text)
    {
        Assert.Throws<FormatException>(() => FastBase64.Decode(text));
        Assert.Throws<FormatException>(() => FastBase64Url.Decode(text));
        if (text.Length % 4 != 0)
        {
            Assert.Throws<FormatException>(() => FastBase64.GetDecodedLength(Encoding.ASCII.GetBytes(text)));
            Assert.Throws<FormatException>(() => FastBase64.GetDecodedLength(text.AsSpan()));
            Assert.Throws<FormatException>(() => FastBase64Url.GetDecodedLength(Encoding.ASCII.GetBytes(text)));
            Assert.Throws<FormatException>(() => FastBase64Url.GetDecodedLength(text.AsSpan()));
        }
    }

    [Theory]
    [MemberData(nameof(Alphabets))]
    public void DecodeIntoSpanReturnsLengthOrThrows(bool url)
    {
        var utf8 = "Zm9vYmFy"u8.ToArray();
        var destination = new byte[16];
        destination.AsSpan().Fill(Marker);

        Decode(url, utf8, destination).Is(6);
        destination.AsSpan(0, 6).SequenceEqual("foobar"u8).IsTrue();
        destination.AsSpan(6).IndexOfAnyExcept(Marker).Is(-1);
        Decode(url, "Zm9vYmFy".AsSpan(), destination).Is(6);
        destination.AsSpan(0, 6).SequenceEqual("foobar"u8).IsTrue();
        destination.AsSpan(6).IndexOfAnyExcept(Marker).Is(-1);

        // The destination must hold the exact decoded length.
        var small = new byte[5];
        TryDecode(url, utf8, small, out var written).IsFalse();
        written.Is(0);
        TryDecode(url, "Zm9vYmFy".AsSpan(), small, out written).IsFalse();
        written.Is(0);
        Assert.Throws<FormatException>(() => Decode(url, utf8, small));
        Assert.Throws<FormatException>(() => Decode(url, "Zm9vYmFy".AsSpan(), small));
    }

    private static void AssertRejected(bool url, string text)
    {
        var utf8 = Encoding.UTF8.GetBytes(text);
        var destination = new byte[utf8.Length + 16];

        TryDecode(url, text.AsSpan(), destination, out var written).IsFalse();
        written.Is(0);
        TryDecode(url, utf8, destination, out written).IsFalse();
        written.Is(0);
        Assert.Throws<FormatException>(() => Decode(url, text));
        Assert.Throws<FormatException>(() => Decode(url, text.AsSpan(), destination));
        Assert.Throws<FormatException>(() => Decode(url, utf8, destination));
    }

    private static bool TryDecode(bool url, ReadOnlySpan<byte> utf8, Span<byte> destination, out int written)
        => url ? FastBase64Url.TryDecode(utf8, destination, out written) : FastBase64.TryDecode(utf8, destination, out written);

    private static bool TryDecode(bool url, ReadOnlySpan<char> chars, Span<byte> destination, out int written)
        => url ? FastBase64Url.TryDecode(chars, destination, out written) : FastBase64.TryDecode(chars, destination, out written);

    private static int Decode(bool url, ReadOnlySpan<byte> utf8, Span<byte> destination)
        => url ? FastBase64Url.Decode(utf8, destination) : FastBase64.Decode(utf8, destination);

    private static int Decode(bool url, ReadOnlySpan<char> chars, Span<byte> destination)
        => url ? FastBase64Url.Decode(chars, destination) : FastBase64.Decode(chars, destination);

    private static byte[] Decode(bool url, string text)
        => url ? FastBase64Url.Decode(text) : FastBase64.Decode(text);
}
