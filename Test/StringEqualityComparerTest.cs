// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Crypto;
using Xunit;

namespace Test;

public class StringEqualityComparerTest
{
    [Fact]
    public void Utf8ComparerRejectsDifferentContent()
    {
        var comparer = new Utf8StringEqualityComparer();
        var stored = "abc"u8.ToArray();
        comparer.Equals("abc"u8, stored).IsTrue();
        comparer.Equals("abd"u8, stored).IsFalse();
        comparer.Equals("ab"u8, stored).IsFalse();
        comparer.Equals("abcd"u8, stored).IsFalse();
        comparer.Equals(ReadOnlySpan<byte>.Empty, stored).IsFalse();
        comparer.Equals(ReadOnlySpan<byte>.Empty, Array.Empty<byte>()).IsTrue();
        comparer.Equals("ab"u8.ToArray(), stored).IsFalse();

        var dictionary = new Dictionary<byte[], int>(Utf8StringEqualityComparer.Default) { [stored] = 1, };
        var lookup = dictionary.GetAlternateLookup<ReadOnlySpan<byte>>();
        lookup.ContainsKey("abc"u8).IsTrue();
        lookup.TryGetValue("abd"u8, out _).IsFalse();
        lookup.ContainsKey("ab"u8).IsFalse();
        lookup.ContainsKey(ReadOnlySpan<byte>.Empty).IsFalse();
        dictionary.ContainsKey("abd"u8.ToArray()).IsFalse();
    }

    [Fact]
    public void Utf16ComparerRejectsDifferentContent()
    {
        var comparer = new Utf16StringEqualityComparer();
        var stored = "日本語".ToCharArray();
        comparer.Equals("日本語".AsSpan(), stored).IsTrue();
        comparer.Equals("日本誤".AsSpan(), stored).IsFalse();
        comparer.Equals("日本".AsSpan(), stored).IsFalse();
        comparer.Equals("日本語!".AsSpan(), stored).IsFalse();
        comparer.Equals("ABC".AsSpan(), "abc".ToCharArray()).IsFalse(); // Ordinal: no case folding.
        comparer.Equals(ReadOnlySpan<char>.Empty, stored).IsFalse();
        comparer.Equals(ReadOnlySpan<char>.Empty, Array.Empty<char>()).IsTrue();
        comparer.Equals("日本".ToCharArray(), stored).IsFalse();

        var dictionary = new Dictionary<char[], int>(Utf16StringEqualityComparer.Default) { [stored] = 1, };
        var lookup = dictionary.GetAlternateLookup<ReadOnlySpan<char>>();
        lookup.ContainsKey("日本語").IsTrue();
        lookup.TryGetValue("日本誤", out _).IsFalse();
        lookup.ContainsKey("日本").IsFalse();
        lookup.ContainsKey(ReadOnlySpan<char>.Empty).IsFalse();
        dictionary.ContainsKey("日本誤".ToCharArray()).IsFalse();
    }

    [Fact]
    public void ArrayAndSpanHashesAgree()
    {
        var utf8 = new Utf8StringEqualityComparer();
        var utf16 = new Utf16StringEqualityComparer();
        var random = new Random(66);
        for (var length = 0; length <= 300; length++)
        {// Covers every XXH3 size class, including inputs over 240 bytes.
            var bytes = new byte[length];
            random.NextBytes(bytes);
            utf8.GetHashCode((ReadOnlySpan<byte>)bytes).Is(utf8.GetHashCode(bytes));
            utf8.GetHashCode(bytes.ToArray()).Is(utf8.GetHashCode(bytes));
            Utf8StringEqualityComparer.Default.GetHashCode(bytes).Is(utf8.GetHashCode(bytes)); // All instances share the seed.

            var chars = new char[length];
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)random.Next(0, 0x10000);
            }

            utf16.GetHashCode((ReadOnlySpan<char>)chars).Is(utf16.GetHashCode(chars));
            utf16.GetHashCode(chars.ToArray()).Is(utf16.GetHashCode(chars));
            Utf16StringEqualityComparer.Default.GetHashCode(chars).Is(utf16.GetHashCode(chars));
        }
    }

    [Fact]
    public void HashesAreSeeded()
    {
        // With a random per-process seed, a hash matches unseeded XXH3 with probability 2^-32, so all 16 match by chance with probability 2^-512.
        var utf8 = new Utf8StringEqualityComparer();
        var utf16 = new Utf16StringEqualityComparer();
        var random = new Random(67);
        var unseeded8 = 0;
        var unseeded16 = 0;
        for (var i = 0; i < 16; i++)
        {
            var bytes = new byte[1 + (i * 20)];
            random.NextBytes(bytes);
            if (utf8.GetHashCode(bytes) == unchecked((int)System.IO.Hashing.XxHash3.HashToUInt64(bytes)))
            {
                unseeded8++;
            }

            var chars = new char[1 + (i * 10)];
            for (var j = 0; j < chars.Length; j++)
            {
                chars[j] = (char)random.Next(0, 0x10000);
            }

            if (utf16.GetHashCode(chars) == unchecked((int)System.IO.Hashing.XxHash3.HashToUInt64(MemoryMarshal.AsBytes(chars.AsSpan()))))
            {
                unseeded16++;
            }
        }

        (unseeded8 < 16).IsTrue();
        (unseeded16 < 16).IsTrue();
    }

    [Fact]
    public void DictionaryFindsStoredKeysOnly()
    {
        var random = new Random(68);
        var byteDictionary = new Dictionary<byte[], int>(Utf8StringEqualityComparer.Default);
        var byteLookup = byteDictionary.GetAlternateLookup<ReadOnlySpan<byte>>();
        var charDictionary = new Dictionary<char[], int>(Utf16StringEqualityComparer.Default);
        var charLookup = charDictionary.GetAlternateLookup<ReadOnlySpan<char>>();
        var storedBytes = new byte[1_000][];
        var absentBytes = new byte[1_000][];
        var storedChars = new char[1_000][];
        var absentChars = new char[1_000][];
        for (var i = 0; i < storedBytes.Length; i++)
        {// The first element separates stored keys from absent ones, and the next two make every key unique.
            storedBytes[i] = CreateKey(random, 0, i);
            absentBytes[i] = CreateKey(random, 1, i);
            storedChars[i] = Array.ConvertAll(CreateKey(random, 0, i), x => (char)(x * 0x101));
            absentChars[i] = Array.ConvertAll(CreateKey(random, 1, i), x => (char)(x * 0x101));
            byteLookup[storedBytes[i]] = i; // Inserting through the span copies the key.
            charDictionary[storedChars[i]] = i;
        }

        byteDictionary.Count.Is(storedBytes.Length);
        charDictionary.Count.Is(storedChars.Length);
        for (var i = 0; i < storedBytes.Length; i++)
        {
            byteDictionary[storedBytes[i].ToArray()].Is(i);
            byteLookup[storedBytes[i]].Is(i);
            byteDictionary.ContainsKey(absentBytes[i]).IsFalse();
            byteLookup.ContainsKey(absentBytes[i]).IsFalse();

            charDictionary[storedChars[i].ToArray()].Is(i);
            charLookup[storedChars[i]].Is(i);
            charDictionary.ContainsKey(absentChars[i]).IsFalse();
            charLookup.ContainsKey(absentChars[i]).IsFalse();
        }
    }

    private static byte[] CreateKey(Random random, byte marker, int index)
    {
        var key = new byte[3 + random.Next(0, 40)];
        random.NextBytes(key);
        key[0] = marker;
        key[1] = (byte)index;
        key[2] = (byte)(index >> 8);
        return key;
    }
}
