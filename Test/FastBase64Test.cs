// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace XunitTest;

public class FastBase64Test
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "Zg==")]
    [InlineData("fo", "Zm8=")]
    [InlineData("foo", "Zm9v")]
    [InlineData("foob", "Zm9vYg==")]
    [InlineData("fooba", "Zm9vYmE=")]
    [InlineData("foobar", "Zm9vYmFy")]
    public void EncodeToString_KnownVectors(string text, string expected)
    {
        byte[] source = Encoding.ASCII.GetBytes(text);

        string actual = Base64.EncodeToString(source);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("f", "Zg==")]
    [InlineData("fo", "Zm8=")]
    [InlineData("foo", "Zm9v")]
    [InlineData("foob", "Zm9vYg==")]
    [InlineData("fooba", "Zm9vYmE=")]
    [InlineData("foobar", "Zm9vYmFy")]
    public void Decode_KnownVectors(string expected, string base64)
    {
        byte[] decoded = Base64.Decode(base64);

        Assert.Equal(Encoding.ASCII.GetBytes(expected), decoded);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 4)]
    [InlineData(2, 4)]
    [InlineData(3, 4)]
    [InlineData(4, 8)]
    [InlineData(5, 8)]
    [InlineData(6, 8)]
    [InlineData(7, 12)]
    [InlineData(100, 136)]
    public void GetEncodedLength_ReturnsExpectedValue(int byteCount, int expected)
    {
        Assert.Equal(expected, Base64.GetEncodedLength(byteCount));
    }

    [Fact]
    public void GetEncodedLength_Negative_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Base64.GetEncodedLength(-1));
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(4, 3)]
    [InlineData(8, 6)]
    [InlineData(12, 9)]
    public void GetMaxDecodedLength_ReturnsExpectedValue(int encodedLength, int expected)
    {
        Assert.Equal(expected, Base64.GetMaxDecodedLength(encodedLength));
    }

    [Fact]
    public void GetMaxDecodedLength_Negative_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Base64.GetMaxDecodedLength(-1));
    }

    [Theory]
    [InlineData("", 0)]
    [InlineData("Zg==", 1)]
    [InlineData("Zm8=", 2)]
    [InlineData("Zm9v", 3)]
    [InlineData("Zm9vYg==", 4)]
    [InlineData("Zm9vYmE=", 5)]
    [InlineData("Zm9vYmFy", 6)]
    public void GetDecodedLength_ReturnsExpectedValue(string base64, int expected)
    {
        Assert.Equal(expected, Base64.GetDecodedLength(base64.AsSpan()));
        Assert.Equal(expected, Base64.GetDecodedLength(Encoding.ASCII.GetBytes(base64)));
    }

    [Theory]
    [InlineData("A")]
    [InlineData("AA=")]
    [InlineData("AAA==")]
    public void GetDecodedLength_InvalidLengthOrPadding_Throws(string base64)
    {
        Assert.Throws<FormatException>(
            () => Base64.GetDecodedLength(base64.AsSpan()));
    }

    [Fact]
    public void Encode_Utf8Destination_ReturnsExpectedResult()
    {
        byte[] source = Encoding.ASCII.GetBytes("foobar");
        byte[] destination = new byte[Base64.GetEncodedLength(source.Length)];

        int written = Base64.Encode(source, destination);

        Assert.Equal(destination.Length, written);
        Assert.Equal("Zm9vYmFy", Encoding.ASCII.GetString(destination));
    }

    [Fact]
    public void Encode_CharDestination_ReturnsExpectedResult()
    {
        byte[] source = Encoding.ASCII.GetBytes("foobar");
        char[] destination = new char[Base64.GetEncodedLength(source.Length)];

        int written = Base64.Encode(source, destination);

        Assert.Equal(destination.Length, written);
        Assert.Equal("Zm9vYmFy", new string(destination));
    }

    [Fact]
    public void Encode_DestinationTooSmall_Throws()
    {
        byte[] source = [1, 2, 3];
        byte[] destination = new byte[3];

        Assert.Throws<ArgumentException>(
            () => Base64.Encode(source, destination));
    }

    [Fact]
    public void Encode_CharDestinationTooSmall_Throws()
    {
        byte[] source = [1, 2, 3];
        char[] destination = new char[3];

        Assert.Throws<ArgumentException>(
            () => Base64.Encode(source, destination));
    }

    [Fact]
    public void TryDecode_Utf8_ReturnsExpectedResult()
    {
        byte[] source = "Zm9vYmFy"u8.ToArray();
        byte[] destination = new byte[6];

        bool result = Base64.TryDecode(source, destination, out int written);

        Assert.True(result);
        Assert.Equal(6, written);
        Assert.Equal("foobar", Encoding.ASCII.GetString(destination));
    }

    [Fact]
    public void TryDecode_Chars_ReturnsExpectedResult()
    {
        const string Source = "Zm9vYmFy";
        byte[] destination = new byte[6];

        bool result = Base64.TryDecode(Source, destination, out int written);

        Assert.True(result);
        Assert.Equal(6, written);
        Assert.Equal("foobar", Encoding.ASCII.GetString(destination));
    }

    [Fact]
    public void TryDecode_DestinationTooSmall_ReturnsFalse()
    {
        byte[] destination = new byte[5];

        bool result = Base64.TryDecode("Zm9vYmFy", destination, out int written);

        Assert.False(result);
        Assert.Equal(0, written);
    }

    [Theory]
    [InlineData("!")]
    [InlineData("####")]
    [InlineData("Zm=v")]
    [InlineData("Zm9v\n")]
    [InlineData("Zm9v ")]
    [InlineData("Zm9v\t")]
    public void TryDecode_InvalidInput_ReturnsFalse(string base64)
    {
        byte[] destination = new byte[128];

        bool result = Base64.TryDecode(base64, destination, out int written);

        Assert.False(result);
        Assert.Equal(0, written);
    }

    [Fact]
    public void Decode_InvalidInput_Throws()
    {
        Assert.Throws<FormatException>(
            () => Base64.Decode("!!!!"));
    }

    [Fact]
    public void Decode_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => Base64.Decode(null!));
    }

    [Fact]
    public void EmptyInput_RoundTrips()
    {
        Assert.Equal(string.Empty, Base64.EncodeToString([]));
        Assert.Empty(Base64.Decode(string.Empty));

        byte[] destination = new byte[1];

        Assert.True(Base64.TryDecode(ReadOnlySpan<char>.Empty, destination, out int written));
        Assert.Equal(0, written);
    }

    [Fact]
    public void RandomData_MatchesConvert()
    {
        var random = new Random(123456);

        for (int length = 0; length <= 1024; length++)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            string expected = Convert.ToBase64String(source);
            string actual = Base64.EncodeToString(source);

            Assert.Equal(expected, actual);

            byte[] decoded = Base64.Decode(actual);

            Assert.Equal(source, decoded);
        }
    }

    [Fact]
    public void RandomData_Utf8EncodingMatchesConvert()
    {
        var random = new Random(654321);

        for (int length = 0; length <= 512; length++)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            int encodedLength = Base64.GetEncodedLength(length);
            byte[] destination = new byte[encodedLength];

            int written = Base64.Encode(source, destination);

            Assert.Equal(encodedLength, written);
            Assert.Equal(
                Convert.ToBase64String(source),
                Encoding.ASCII.GetString(destination));
        }
    }

    [Fact]
    public void RandomData_CharEncodingMatchesConvert()
    {
        var random = new Random(789012);

        for (int length = 0; length <= 512; length++)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            int encodedLength = Base64.GetEncodedLength(length);
            char[] destination = new char[encodedLength];

            int written = Base64.Encode(source, destination);

            Assert.Equal(encodedLength, written);
            Assert.Equal(
                Convert.ToBase64String(source),
                new string(destination));
        }
    }

    [Fact]
    public void SimdBoundaryLengths_RoundTrip()
    {
        int[] lengths =
        [
            0,
            1,
            2,
            3,
            11,
            12,
            13,
            15,
            16,
            17,
            23,
            24,
            25,
            31,
            32,
            33,
            47,
            48,
            49,
            63,
            64,
            65,
            95,
            96,
            97,
            127,
            128,
            129,
        ];

        var random = new Random(1234);

        foreach (int length in lengths)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            string encoded = Base64.EncodeToString(source);
            byte[] decoded = Base64.Decode(encoded);

            Assert.Equal(Convert.ToBase64String(source), encoded);
            Assert.Equal(source, decoded);
        }
    }
}

public class FastBase64UrlTest
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "Zg")]
    [InlineData("fo", "Zm8")]
    [InlineData("foo", "Zm9v")]
    [InlineData("foob", "Zm9vYg")]
    [InlineData("fooba", "Zm9vYmE")]
    [InlineData("foobar", "Zm9vYmFy")]
    public void EncodeToString_KnownVectors(string text, string expected)
    {
        byte[] source = Encoding.ASCII.GetBytes(text);

        string actual = Base64Url.EncodeToString(source);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 2)]
    [InlineData(2, 3)]
    [InlineData(3, 4)]
    [InlineData(4, 6)]
    [InlineData(5, 7)]
    [InlineData(6, 8)]
    [InlineData(7, 10)]
    public void GetEncodedLength_ReturnsExpectedValue(int byteCount, int expected)
    {
        Assert.Equal(expected, Base64Url.GetEncodedLength(byteCount));
    }

    [Theory]
    [InlineData("Zg", "f")]
    [InlineData("Zg==", "f")]
    [InlineData("Zm8", "fo")]
    [InlineData("Zm8=", "fo")]
    [InlineData("Zm9v", "foo")]
    public void Decode_AcceptsPaddedAndUnpaddedInput(string encoded, string expected)
    {
        byte[] decoded = Base64Url.Decode(encoded);

        Assert.Equal(Encoding.ASCII.GetBytes(expected), decoded);
    }

    [Fact]
    public void Alphabet_UsesMinusAndUnderscore()
    {
        byte[] source = [0xFB, 0xFF, 0xFF];

        string standard = Convert.ToBase64String(source);
        string url = Base64Url.EncodeToString(source);

        Assert.Equal("+///", standard);
        Assert.Equal("-___", url);
    }

    [Fact]
    public void Decode_RejectsStandardAlphabetSymbols()
    {
        byte[] destination = new byte[16];

        Assert.False(Base64Url.TryDecode("+///", destination, out _));
        Assert.False(Base64Url.TryDecode("////", destination, out _));
    }

    [Fact]
    public void StandardDecoder_RejectsUrlAlphabetSymbols()
    {
        byte[] destination = new byte[16];

        Assert.False(Base64.TryDecode("-___", destination, out _));
    }

    [Theory]
    [InlineData("!")]
    [InlineData("####")]
    [InlineData("Zm-v=")]
    [InlineData("Zm9v\n")]
    [InlineData("Zm9v ")]
    public void TryDecode_InvalidInput_ReturnsFalse(string encoded)
    {
        byte[] destination = new byte[128];

        bool result = Base64Url.TryDecode(encoded, destination, out int written);

        Assert.False(result);
        Assert.Equal(0, written);
    }

    [Fact]
    public void RandomData_RoundTrips()
    {
        var random = new Random(987654);

        for (int length = 0; length <= 1024; length++)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            string encoded = Base64Url.EncodeToString(source);

            // Base64Url must not contain standard Base64 symbols or padding.
            Assert.DoesNotContain('+', encoded);
            Assert.DoesNotContain('/', encoded);
            Assert.DoesNotContain('=', encoded);

            byte[] decoded = Base64Url.Decode(encoded);

            Assert.Equal(source, decoded);
        }
    }

    [Fact]
    public void RandomData_MatchesReferenceTransformation()
    {
        var random = new Random(345678);

        for (int length = 0; length <= 1024; length++)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            string expected = Convert.ToBase64String(source)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            string actual = Base64Url.EncodeToString(source);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void SimdBoundaryLengths_RoundTrip()
    {
        int[] lengths =
        [
            0,
            1,
            2,
            3,
            11,
            12,
            13,
            15,
            16,
            17,
            23,
            24,
            25,
            31,
            32,
            33,
            47,
            48,
            49,
            63,
            64,
            65,
            95,
            96,
            97,
            127,
            128,
            129,
        ];

        var random = new Random(5678);

        foreach (int length in lengths)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            string encoded = Base64Url.EncodeToString(source);
            byte[] decoded = Base64Url.Decode(encoded);

            Assert.Equal(source, decoded);
        }
    }

    [Fact]
    public void Utf8AndCharApis_ProduceSameResult()
    {
        var random = new Random(111222);

        for (int length = 0; length <= 256; length++)
        {
            byte[] source = new byte[length];
            random.NextBytes(source);

            int encodedLength = Base64Url.GetEncodedLength(length);

            byte[] utf8 = new byte[encodedLength];
            char[] chars = new char[encodedLength];

            int utf8Written = Base64Url.Encode(source, utf8);
            int charsWritten = Base64Url.Encode(source, chars);

            Assert.Equal(encodedLength, utf8Written);
            Assert.Equal(encodedLength, charsWritten);

            Assert.Equal(
                Encoding.ASCII.GetString(utf8),
                new string(chars));
        }
    }
}
