// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Base32SortTest
{
    private const string Alphabet = "0123456789ABCEFGHJKMNPQRSTUVWXYZ";
    private const string RfcAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private static readonly IBase32Converter[] Converters = [Base32Sort.Reference, Base32Sort.Table,];

    // RFC 4648, section 10 (standard Base32 alphabet, padded). Base32Sort uses the same bit layout with another alphabet
    // and no padding, so each vector maps over by substituting characters and dropping '='.
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY======")]
    [InlineData("fo", "MZXQ====")]
    [InlineData("foo", "MZXW6===")]
    [InlineData("foob", "MZXW6YQ=")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI======")]
    public void Rfc4648Vectors(string plain, string rfcBase32)
    {
        var expected = string.Concat(rfcBase32.TrimEnd('=').Select(c => Alphabet[RfcAlphabet.IndexOf(c)]));
        var source = Encoding.ASCII.GetBytes(plain);
        foreach (var converter in Converters)
        {
            AssertRoundTrip(converter, source, expected);
        }
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("00", "00")]
    [InlineData("FF", "ZW")]
    [InlineData("FFFFFFFFFF", "ZZZZZZZZ")]
    [InlineData("666F6F626172", "CTRQYSM1F8")] // "foobar"
    [InlineData("00443214C74254B635CF84653A56D7C675BE77DF", "0123456789ABCEFGHJKMNPQRSTUVWXYZ")] // The 5-bit values 0 to 31, packed most significant bit first.
    public void KnownVectors(string hex, string expected)
    {
        var source = Convert.FromHexString(hex);
        Assert.Equal(expected, EncodeWithBitString(source)); // The oracle agrees with the hand-derived vector.
        foreach (var converter in Converters)
        {
            AssertRoundTrip(converter, source, expected);
        }
    }

    [Fact]
    public void EncodingPreservesByteOrder()
    {
        // The alphabet is strictly ascending in ordinal order.
        for (var value = 0; value < 32; value++)
        {
            foreach (var converter in Converters)
            {
                converter.FromBytesToString([(byte)(value << 3)])[0].Is(Alphabet[value]);
            }

            if (value > 0)
            {
                (Alphabet[value - 1] < Alphabet[value]).IsTrue();
            }
        }

        // Oracle: lexicographic byte order of the sources.
        var random = new Random(7);
        byte[] smallValues = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF,];
        for (var i = 0; i < 20_000; i++)
        {
            var a = new byte[random.Next(0, 12)];
            var b = new byte[random.Next(0, 12)];
            if ((i & 1) == 0)
            {
                random.NextBytes(a);
                random.NextBytes(b);
            }
            else
            {// Few distinct values make ties, prefixes and near-equal arrays common.
                FillFrom(random, a, smallValues);
                FillFrom(random, b, smallValues);
            }

            if ((i & 3) == 0)
            {// b starts with a prefix of a (possibly all of it).
                b = [.. a.AsSpan(0, random.Next(0, a.Length + 1)), .. b.AsSpan(0, random.Next(0, b.Length + 1))];
            }

            var expected = Math.Sign(a.AsSpan().SequenceCompareTo(b));
            foreach (var converter in Converters)
            {
                Math.Sign(string.CompareOrdinal(converter.FromBytesToString(a), converter.FromBytesToString(b))).Is(expected);
                Math.Sign(converter.FromBytesToUtf8(a).AsSpan().SequenceCompareTo(converter.FromBytesToUtf8(b))).Is(expected);
            }
        }
    }

    [Fact]
    public void DecodingAcceptsDocumentedCharactersOnly()
    {
        var destination = new byte[8];
        for (var c = 0; c < 0x180; c++)
        {
            var ch = (char)c;
            var value = ExpectedValue(ch);
            var block = ch + "0000000"; // Full eight-character block.
            var tail = ch + "0"; // Two-character tail.
            foreach (var converter in Converters)
            {
                if (value < 0)
                {
                    converter.FromStringToSpan(block, destination, out var written).IsFalse();
                    written.Is(0);
                    converter.FromStringToSpan(tail, destination, out written).IsFalse();
                    written.Is(0);
                    converter.FromStringToByteArray(tail).Length.Is(0);
                    if (c <= 0xFF)
                    {
                        converter.FromUtf8ToSpan(Latin1(block), destination, out written).IsFalse();
                        written.Is(0);
                        converter.FromUtf8ToByteArray(Latin1(tail)).Length.Is(0);
                    }
                }
                else
                {
                    var expected = (byte)(value << 3);
                    converter.FromStringToSpan(block, destination, out var written).IsTrue();
                    written.Is(5);
                    destination[0].Is(expected);
                    destination.AsSpan(1, 4).IndexOfAnyExcept((byte)0).Is(-1);
                    Assert.Equal(new byte[] { expected, }, converter.FromStringToByteArray(tail));
                    converter.FromUtf8ToSpan(Latin1(block), destination, out written).IsTrue();
                    written.Is(5);
                    destination[0].Is(expected);
                    Assert.Equal(new byte[] { expected, }, converter.FromUtf8ToByteArray(Latin1(tail)));
                }
            }
        }
    }

    [Theory]
    [InlineData("0D")]
    [InlineData("0d")]
    [InlineData("0L")]
    [InlineData("D0000000")]
    [InlineData("0000000d")]
    [InlineData("L0000000")]
    [InlineData("00!")] // A trailing character that carries no complete byte is still validated.
    [InlineData("00000L")]
    [InlineData("00000000D")]
    public void ExcludedLettersAreRejected(string base32)
    {
        var destination = new byte[8];
        foreach (var converter in Converters)
        {
            converter.FromStringToSpan(base32, destination, out var written).IsFalse();
            written.Is(0);
            converter.FromUtf8ToSpan(Encoding.ASCII.GetBytes(base32), destination, out written).IsFalse();
            written.Is(0);
            converter.FromStringToByteArray(base32).Length.Is(0);
            converter.FromUtf8ToByteArray(Encoding.ASCII.GetBytes(base32)).Length.Is(0);
        }
    }

    [Theory]
    [InlineData("I0000000", "10000000")]
    [InlineData("i0000000", "10000000")]
    [InlineData("l0000000", "10000000")]
    [InlineData("OZ", "0Z")]
    [InlineData("oZ", "0Z")]
    [InlineData("u0000000", "U0000000")]
    [InlineData("ZZZZZZZZIilOo", "ZZZZZZZZ11100")]
    public void AliasesDecodeAsTheirCanonicalCharacter(string alias, string canonical)
    {
        var expected = DecodeWithBitString(canonical);
        foreach (var converter in Converters)
        {
            Assert.Equal(expected, converter.FromStringToByteArray(alias));
            Assert.Equal(expected, converter.FromUtf8ToByteArray(Encoding.ASCII.GetBytes(alias)));
            Assert.Equal(expected, converter.FromStringToByteArray(canonical));
        }
    }

    // Decoding is lenient: trailing bits that do not complete a byte are ignored, including a whole trailing character
    // when the length modulo 8 is 1, 3 or 6. The expected bytes are worked out by hand from the 5-bit values.
    [Theory]
    [InlineData("0", "")]
    [InlineData("Z", "")]
    [InlineData("00", "00")]
    [InlineData("03", "00")] // The low two bits of '3' are unused.
    [InlineData("04", "01")]
    [InlineData("07", "01")]
    [InlineData("0Z", "07")]
    [InlineData("000", "00")]
    [InlineData("00Z", "00")] // The third character carries no complete byte.
    [InlineData("000Z", "0001")] // The low four bits of 'Z' are unused.
    [InlineData("00000Z", "000000")] // The sixth character carries no complete byte.
    [InlineData("00000000Z", "0000000000")] // The ninth character carries no complete byte.
    [InlineData("ZZZZZZZZZ", "FFFFFFFFFF")]
    public void DecodingIgnoresTrailingBits(string base32, string expectedHex)
    {
        var expected = Convert.FromHexString(expectedHex);
        Assert.Equal(expected, DecodeWithBitString(base32));
        var destination = new byte[8];
        foreach (var converter in Converters)
        {
            converter.FromStringToSpan(base32, destination, out var written).IsTrue();
            Assert.Equal(expected, destination.AsSpan(0, written).ToArray());
            converter.FromUtf8ToSpan(Encoding.ASCII.GetBytes(base32), destination, out written).IsTrue();
            Assert.Equal(expected, destination.AsSpan(0, written).ToArray());
            Assert.Equal(expected, converter.FromStringToByteArray(base32));
            Assert.Equal(expected, converter.FromStringToByteArray(base32.ToLowerInvariant()));
            Assert.Equal(expected, converter.FromUtf8ToByteArray(Encoding.ASCII.GetBytes(base32)));
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(9)]
    [InlineData(16)]
    [InlineData(33)]
    public void ShortDestinationIsRejectedWithoutWriting(int length)
    {
        var source = new byte[length];
        new Random(length).NextBytes(source);
        var encodedLength = Base32Sort.GetEncodedLength(length);
        Base32Sort.GetDecodedLength(encodedLength).Is(length);
        foreach (var converter in Converters)
        {
            var text = converter.FromBytesToString(source);
            var utf8 = converter.FromBytesToUtf8(source);

            var chars = new char[encodedLength + 8];
            chars.AsSpan().Fill('#');
            converter.FromBytesToSpan(source, chars.AsSpan(0, encodedLength - 1), out var written).IsFalse();
            written.Is(0);
            chars.AsSpan().IndexOfAnyExcept('#').Is(-1);
            converter.FromBytesToSpan(source, chars, out written).IsTrue();
            written.Is(encodedLength);
            new string(chars, 0, written).Is(text);
            chars.AsSpan(written).IndexOfAnyExcept('#').Is(-1);

            var bytes = new byte[encodedLength + 8];
            bytes.AsSpan().Fill(0xAA);
            converter.FromBytesToSpan(source, bytes.AsSpan(0, encodedLength - 1), out written).IsFalse();
            written.Is(0);
            bytes.AsSpan().IndexOfAnyExcept((byte)0xAA).Is(-1);
            converter.FromBytesToSpan(source, bytes, out written).IsTrue();
            written.Is(encodedLength);
            bytes.AsSpan(0, written).SequenceEqual(utf8).IsTrue();
            bytes.AsSpan(written).IndexOfAnyExcept((byte)0xAA).Is(-1);

            var decoded = new byte[length + 8];
            decoded.AsSpan().Fill(0xAA);
            converter.FromStringToSpan(text, decoded.AsSpan(0, length - 1), out written).IsFalse();
            written.Is(0);
            converter.FromUtf8ToSpan(utf8, decoded.AsSpan(0, length - 1), out written).IsFalse();
            written.Is(0);
            decoded.AsSpan().IndexOfAnyExcept((byte)0xAA).Is(-1);

            converter.FromStringToSpan(text, decoded, out written).IsTrue();
            written.Is(length);
            decoded.AsSpan(0, written).SequenceEqual(source).IsTrue();
            decoded.AsSpan(written).IndexOfAnyExcept((byte)0xAA).Is(-1);

            decoded.AsSpan().Fill(0x55);
            converter.FromUtf8ToSpan(utf8, decoded, out written).IsTrue();
            written.Is(length);
            decoded.AsSpan(0, written).SequenceEqual(source).IsTrue();
            decoded.AsSpan(written).IndexOfAnyExcept((byte)0x55).Is(-1);
        }
    }

    [Fact]
    public void FailedDecodingDoesNotWritePastTheDecodedLength()
    {
        // An invalid character in the second block: the first block may already be written, but nothing beyond the decoded length is.
        const string Base32 = "ZZZZZZZZ*ZZZZZZZ";
        var decodedLength = Base32Sort.GetDecodedLength(Base32.Length);
        foreach (var converter in Converters)
        {
            var destination = new byte[decodedLength + 8];
            destination.AsSpan().Fill(0xAA);
            converter.FromStringToSpan(Base32, destination, out var written).IsFalse();
            written.Is(0);
            destination.AsSpan(decodedLength).IndexOfAnyExcept((byte)0xAA).Is(-1);

            destination.AsSpan().Fill(0xAA);
            converter.FromUtf8ToSpan(Encoding.ASCII.GetBytes(Base32), destination, out written).IsFalse();
            written.Is(0);
            destination.AsSpan(decodedLength).IndexOfAnyExcept((byte)0xAA).Is(-1);
        }
    }

    [Fact]
    public void ConvertersMatchBitStringOracle()
    {
        var random = new Random(71);
        for (var length = 0; length <= 200; length++)
        {
            for (var round = 0; round < 3; round++)
            {
                var source = new byte[length];
                if (round == 1)
                {
                    source.AsSpan().Fill(0xFF);
                }
                else
                {
                    random.NextBytes(source);
                }

                var expected = EncodeWithBitString(source);
                foreach (var converter in Converters)
                {
                    AssertRoundTrip(converter, source, expected);
                }
            }
        }

        // Arbitrary valid text (lower case, aliases, any length) and the same text with one invalid character.
        const string Symbols = "0123456789ABCEFGHJKMNPQRSTUVWXYZabcefghjkmnpqrstuvwxyzIilOo";
        char[] invalid = ['!', 'L', 'D', 'd', (char)0x130,];
        var destination = new byte[256];
        for (var length = 0; length <= 200; length++)
        {
            var chars = new char[length];
            for (var i = 0; i < length; i++)
            {
                chars[i] = Symbols[random.Next(Symbols.Length)];
            }

            var text = new string(chars);
            var expected = DecodeWithBitString(text);
            foreach (var converter in Converters)
            {
                converter.FromStringToSpan(text, destination, out var written).IsTrue();
                destination.AsSpan(0, written).SequenceEqual(expected).IsTrue();
                converter.FromUtf8ToSpan(Encoding.ASCII.GetBytes(text), destination, out written).IsTrue();
                destination.AsSpan(0, written).SequenceEqual(expected).IsTrue();
                converter.FromStringToByteArray(text).SequenceEqual(expected).IsTrue();
                converter.FromUtf8ToByteArray(Encoding.ASCII.GetBytes(text)).SequenceEqual(expected).IsTrue();
            }

            if (length > 0)
            {
                chars[random.Next(length)] = invalid[random.Next(invalid.Length)];
                text = new string(chars);
                foreach (var converter in Converters)
                {
                    converter.FromStringToSpan(text, destination, out var written).IsFalse();
                    written.Is(0);
                    converter.FromUtf8ToSpan(Encoding.UTF8.GetBytes(text), destination, out written).IsFalse();
                    written.Is(0);
                    converter.FromStringToByteArray(text).Length.Is(0);
                    converter.FromUtf8ToByteArray(Encoding.UTF8.GetBytes(text)).Length.Is(0);
                }
            }
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(1 << 30)]
    [InlineData(int.MaxValue - 4)]
    [InlineData(int.MaxValue - 1)]
    [InlineData(int.MaxValue)]
    [InlineData(-1)]
    [InlineData(-5)]
    [InlineData(-7)]
    [InlineData(int.MinValue)]
    public void FastMod5ReducesTheUnsignedValue(int value)
    {
        var expected = (int)((uint)value % 5);
        Base32Sort.FastMod5(value).Is(expected);

        // Both platform paths, whatever the bitness of the test process.
        Base32Sort.Mod5ByMultiplication(value).Is(expected);
        Base32Sort.Mod5ByDivision(value).Is(expected);
    }

    [Fact]
    public void FastMod5MatchesRemainderOperator()
    {
        for (var value = 0; value <= 100_000; value++)
        {
            AssertMod5(value, value % 5);
        }

        var random = new Random(5);
        for (var i = 0; i < 1_000_000; i++)
        {
            var value = (uint)random.NextInt64(0, 1L << 32);
            AssertMod5(unchecked((int)value), (int)(value % 5));
        }

        static void AssertMod5(int value, int expected)
        {
            if (Base32Sort.FastMod5(value) != expected ||
                Base32Sort.Mod5ByMultiplication(value) != expected ||
                Base32Sort.Mod5ByDivision(value) != expected)
            {
                Assert.Fail($"FastMod5({value})");
            }
        }
    }

    private static void AssertRoundTrip(IBase32Converter converter, byte[] source, string expected)
    {
        var utf8 = Encoding.ASCII.GetBytes(expected);
        converter.FromBytesToString(source).Is(expected);
        converter.FromBytesToUtf8(source).AsSpan().SequenceEqual(utf8).IsTrue();

        var chars = new char[expected.Length];
        converter.FromBytesToSpan(source, chars, out var written).IsTrue();
        written.Is(expected.Length);
        new string(chars).Is(expected);
        var bytes = new byte[expected.Length];
        converter.FromBytesToSpan(source, bytes, out written).IsTrue();
        written.Is(expected.Length);
        bytes.AsSpan().SequenceEqual(utf8).IsTrue();

        converter.FromStringToByteArray(expected).AsSpan().SequenceEqual(source).IsTrue();
        converter.FromStringToByteArray(expected.ToLowerInvariant()).AsSpan().SequenceEqual(source).IsTrue();
        converter.FromUtf8ToByteArray(utf8).AsSpan().SequenceEqual(source).IsTrue();
        var decoded = new byte[source.Length];
        converter.FromStringToSpan(expected, decoded, out written).IsTrue();
        written.Is(source.Length);
        decoded.AsSpan().SequenceEqual(source).IsTrue();
        decoded.AsSpan().Clear();
        converter.FromUtf8ToSpan(utf8, decoded, out written).IsTrue();
        written.Is(source.Length);
        decoded.AsSpan().SequenceEqual(source).IsTrue();
    }

    /// <summary>
    /// Independent oracle: writes the bytes as a bit string, pads it with zeros to a multiple of five bits and maps each 5-bit group.
    /// </summary>
    private static string EncodeWithBitString(ReadOnlySpan<byte> source)
    {
        var bits = new StringBuilder();
        foreach (var b in source)
        {
            bits.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
        }

        while (bits.Length % 5 != 0)
        {
            bits.Append('0');
        }

        var result = new StringBuilder();
        for (var i = 0; i < bits.Length; i += 5)
        {
            result.Append(Alphabet[Convert.ToInt32(bits.ToString(i, 5), 2)]);
        }

        return result.ToString();
    }

    /// <summary>
    /// Independent oracle: concatenates the 5-bit values and keeps only complete bytes.
    /// </summary>
    private static byte[] DecodeWithBitString(string base32)
    {
        var bits = new StringBuilder();
        foreach (var c in base32)
        {
            bits.Append(Convert.ToString(ExpectedValue(c), 2).PadLeft(5, '0'));
        }

        var result = new byte[bits.Length / 8];
        for (var i = 0; i < result.Length; i++)
        {
            result[i] = Convert.ToByte(bits.ToString(i * 8, 8), 2);
        }

        return result;
    }

    /// <summary>
    /// Gets the documented 5-bit value of a character, or -1 if the character is rejected.
    /// </summary>
    private static int ExpectedValue(char c)
    {
        if (c is 'I' or 'i' or 'l')
        {
            return 1;
        }
        else if (c is 'O' or 'o')
        {
            return 0;
        }
        else if (c is >= 'a' and <= 'z')
        {
            c = (char)(c - 'a' + 'A');
        }

        return Alphabet.IndexOf(c);
    }

    private static byte[] Latin1(string text)
        => Encoding.Latin1.GetBytes(text);

    private static void FillFrom(Random random, byte[] destination, byte[] values)
    {
        for (var i = 0; i < destination.Length; i++)
        {
            destination[i] = values[random.Next(values.Length)];
        }
    }
}
