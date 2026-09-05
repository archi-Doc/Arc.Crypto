// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class UtilityCoverageTest
{
    [Fact]
    public void ComparersSupportAlternateLookupsAndNulls()
    {
        var utf8 = new Utf8StringEqualityComparer();
        Assert.True(utf8.Equals((byte[]?)null, null));
        Assert.False(utf8.Equals((byte[]?)null, []));
        Assert.False(utf8.Equals(Array.Empty<byte>(), (byte[]?)null));
        Assert.False(utf8.Equals(ReadOnlySpan<byte>.Empty, null!));
        Assert.True(utf8.Equals("abc"u8.ToArray(), "abc"u8.ToArray()));
        Assert.False(utf8.Equals("abc"u8.ToArray(), "abd"u8.ToArray()));
        Assert.Equal(utf8.GetHashCode("abc"u8), utf8.GetHashCode("abc"u8.ToArray()));
        var bytes = "abc"u8.ToArray();
        var copy = utf8.Create(bytes);
        bytes[0] = 0;
        Assert.Equal("abc"u8.ToArray(), copy);
        var dictionary = new Dictionary<byte[], int>(Utf8StringEqualityComparer.Default);
        var lookup = dictionary.GetAlternateLookup<ReadOnlySpan<byte>>();
        lookup["abc"u8] = 42;
        Assert.Equal(42, lookup["abc"u8]);
        Assert.Equal(42, dictionary["abc"u8.ToArray()]);

        var utf16 = new Utf16StringEqualityComparer();
        Assert.True(utf16.Equals((char[]?)null, null));
        Assert.False(utf16.Equals((char[]?)null, []));
        Assert.False(utf16.Equals(Array.Empty<char>(), (char[]?)null));
        Assert.False(utf16.Equals(ReadOnlySpan<char>.Empty, null!));
        Assert.True(utf16.Equals("abc".ToCharArray(), "abc".ToCharArray()));
        Assert.False(utf16.Equals("abc".ToCharArray(), "abd".ToCharArray()));
        Assert.Equal(utf16.GetHashCode("abc".AsSpan()), utf16.GetHashCode("abc".ToCharArray()));
        var chars = "abc".ToCharArray();
        var charCopy = utf16.Create(chars);
        chars[0] = '\0';
        Assert.Equal("abc".ToCharArray(), charCopy);
        var charDictionary = new Dictionary<char[], int>(Utf16StringEqualityComparer.Default);
        var charLookup = charDictionary.GetAlternateLookup<ReadOnlySpan<char>>();
        charLookup["日本語"] = 42;
        Assert.Equal(42, charLookup["日本語"]);
        Assert.Equal(42, charDictionary["日本語".ToCharArray()]);
    }

    [Fact]
    public void XorshiftKnownStatesAndByteTails()
    {
        uint state32 = 1;
        Xorshift.Xor32(ref state32);
        Assert.Equal(270369U, state32);
        Assert.Equal(state32, Xorshift.Xor32(1));
        state32 = 0;
        Xorshift.Xor32(ref state32);
        Assert.Equal(2463534242U, state32);
        Assert.Equal(state32, Xorshift.Xor32(0));
        ulong state64 = 1;
        Xorshift.Xor64(ref state64);
        Assert.Equal(1082269761UL, state64);
        Assert.Equal(state64, Xorshift.Xor64(1));
        state64 = 0;
        Xorshift.Xor64(ref state64);
        Assert.Equal(88172645463325252UL, state64);
        Assert.Equal(state64, Xorshift.Xor64(0));
        Assert.Equal(new Xorshift(state64).NextUInt64(), new Xorshift().NextUInt64());
        for (var length = 0; length < 32; length++)
        {
            var random = new Xorshift(42);
            var reference = new Xorshift(42);
            var words = new ulong[(length + 7) / 8];
            for (var i = 0; i < words.Length; i++)
            {
                words[i] = reference.NextUInt64();
            }

            var output = Enumerable.Repeat((byte)0xA5, length + 2).ToArray();
            random.NextBytes(output.AsSpan(1, length));
            Assert.Equal(MemoryMarshal.AsBytes(words.AsSpan())[..length].ToArray(), output[1..^1]);
            Assert.Equal(0xA5, output[0]);
            Assert.Equal(0xA5, output[^1]);
            Assert.Equal(reference.NextUInt64(), random.NextUInt64());
        }
    }

    [Fact]
    public void MersenneTwisterValidatesSeedsBeforeReading()
    {
        Assert.Throws<ArgumentNullException>(() => new MersenneTwister((byte[])null!));
        Assert.Throws<ArgumentNullException>(() => new MersenneTwister((ulong[])null!));
        Assert.Throws<ArgumentException>(() => new MersenneTwister(Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => new MersenneTwister(Array.Empty<ulong>()));
        Assert.Throws<ArgumentException>(() => new MersenneTwister(new byte[7]));
        Assert.Throws<ArgumentException>(() => new MersenneTwister(new byte[9]));
        var words = new ulong[] { 1, 2, 3, };
        var fromBytes = new MersenneTwister(MemoryMarshal.AsBytes(words.AsSpan()).ToArray());
        var fromWords = new MersenneTwister(words);
        for (var i = 0; i < 1_000; i++)
        {
            Assert.Equal(fromWords.NextUInt64(), fromBytes.NextUInt64());
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(4096)]
    public void TemporaryPasswordStorageIsCleared(int length)
    {
        var password = new string('p', length) + "日本語\0";
        Span<byte> buffer = stackalloc byte[Utf8Password.StackSize];
        var utf8 = new Utf8Password(password, buffer);
        var view = utf8.Bytes;
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes(password), view.ToArray());
        utf8.Dispose();
        Assert.True(view.IndexOfAnyExcept((byte)0) < 0);
        utf8.Dispose();
    }
}
