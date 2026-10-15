// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Sha3HelperTest
{
    private const string PlatformSha3Missing = "The platform does not provide SHA-3.";

    private delegate void SpanHash(ReadOnlySpan<byte> input, Span<byte> output);

    // SHA3-224 test vectors from https://www.di-mgt.com.au/sha_testvectors.html: "abc", the empty string, the 448- and 896-bit messages and one million "a".
    // The message is the first value repeated the given number of times.
    public static TheoryData<string, int, string> Sha3_224Vectors => new()
    {
        { "abc", 1, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
        { string.Empty, 1, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1, "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1, "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc" },
        { "a", 1_000_000, "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c" },
    };

    private static bool IsPlatformSha3Supported => SHA3_256.IsSupported && SHA3_384.IsSupported && SHA3_512.IsSupported;

    [Fact]
    public void MatchesSystemImplementation()
    {
        Assert.SkipUnless(IsPlatformSha3Supported, PlatformSha3Missing);

        var data = new byte[1000];
        new Xoshiro256StarStar(23).NextBytes(data);

        // Lengths around the 72/104/136-byte rates of SHA3-512/384/256.
        foreach (var length in new[] { 0, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 271, 272, 273, 1000 })
        {
            var input = data.AsSpan(0, length);
            var expected256 = SHA3_256.HashData(input);
            var expected384 = SHA3_384.HashData(input);
            var expected512 = SHA3_512.HashData(input);

            Assert.Equal(expected256, Sha3Helper.Get256ByteArray(input));
            Assert.Equal(expected384, Sha3Helper.Get384ByteArray(input));
            Assert.Equal(expected512, Sha3Helper.Get512ByteArray(input));

            AssertSpan(expected256, input, Sha3Helper.Get256Span);
            AssertSpan(expected384, input, Sha3Helper.Get384Span);
            AssertSpan(expected512, input, Sha3Helper.Get512Span);

            var w256 = Sha3Helper.Get256UInt64(input);
            Assert.Equal(expected256, ToBytes(w256.Hash0, w256.Hash1, w256.Hash2, w256.Hash3));
            var w384 = Sha3Helper.Get384UInt64(input);
            Assert.Equal(expected384, ToBytes(w384.Hash0, w384.Hash1, w384.Hash2, w384.Hash3, w384.Hash4, w384.Hash5));
            var w512 = Sha3Helper.Get512UInt64(input);
            Assert.Equal(expected512, ToBytes(w512.Hash0, w512.Hash1, w512.Hash2, w512.Hash3, w512.Hash4, w512.Hash5, w512.Hash6, w512.Hash7));
        }
    }

    [Fact]
    public void SpanOverloadsRejectShortOutput()
    {
        var buffer = new byte[80];
        Array.Fill(buffer, (byte)0xA5);
        Assert.Throws<ArgumentException>(() => Sha3Helper.Get256Span("abc"u8, buffer.AsSpan(0, 31)));
        Assert.Throws<ArgumentException>(() => Sha3Helper.Get384Span("abc"u8, buffer.AsSpan(0, 47)));
        Assert.Throws<ArgumentException>(() => Sha3Helper.Get512Span("abc"u8, buffer.AsSpan(0, 63)));
        Assert.Throws<ArgumentException>(() => new Sha3_256().GetHash("abc"u8, buffer.AsSpan(0, 31)));
        Assert.All(buffer, x => x.Is((byte)0xA5));
    }

    [Fact]
    public void ArrayOverloadsHonorOffset()
    {
        var buffer = new byte[300];
        new Xoshiro256StarStar(24).NextBytes(buffer);
        var slice = buffer.AsSpan(7, 200);

        // The oracle is the platform SHA-3 when available; otherwise the one-shot Sha3Helper, so the offset checks still run.
        var sha3Supported = IsPlatformSha3Supported;
        (Sha3 Hash, byte[] Expected)[] cases =
        [
            (new Sha3_256(), sha3Supported ? SHA3_256.HashData(slice) : Sha3Helper.Get256ByteArray(slice)),
            (new Sha3_384(), sha3Supported ? SHA3_384.HashData(slice) : Sha3Helper.Get384ByteArray(slice)),
            (new Sha3_512(), sha3Supported ? SHA3_512.HashData(slice) : Sha3Helper.Get512ByteArray(slice)),
        ];

        foreach (var (hash, expected) in cases)
        {
            Assert.Equal(expected, hash.GetHash(buffer, 7, 200));
            Assert.Equal(expected, hash.GetHash(slice));

            hash.HashInitialize();
            hash.HashUpdate(buffer, 7, 100);
            hash.HashUpdate(buffer, 107, 100);
            Assert.Equal(expected, hash.HashFinal());

            Assert.ThrowsAny<ArgumentException>(() => hash.GetHash(new byte[4], 5, 1));
            Assert.ThrowsAny<ArgumentException>(() => hash.GetHash(new byte[4], 1, 4));
            Assert.ThrowsAny<ArgumentException>(() => hash.HashUpdate(new byte[4], 1, 4));
        }

        var sha3 = new Sha3_256();
        var words = sha3.GetHashUInt64(buffer, 7, 200);
        Assert.Equal(cases[0].Expected, ToBytes(words.Hash0, words.Hash1, words.Hash2, words.Hash3));
        Assert.Equal(words, sha3.GetHashUInt64(slice));
    }

    [Fact]
    public void HashFinalResetsAndValidatesOutput()
    {
        var sha3 = new Sha3_256();
        sha3.HashUpdate("ab"u8);

        // A short buffer throws before the state is touched, so the calculation can continue.
        Assert.Throws<ArgumentException>(() => sha3.HashFinal(new byte[31]));
        sha3.HashUpdate("c"u8);

        var output = new byte[40];
        Array.Fill(output, (byte)0xA5);
        sha3.HashFinal(output);
        Assert.Equal(Sha3Helper.Get256ByteArray("abc"u8), output.AsSpan(0, 32).ToArray());
        Assert.All(output.AsSpan(32).ToArray(), x => x.Is((byte)0xA5));

        // HashFinal resets the state.
        sha3.HashFinal(output);
        Assert.Equal(Sha3Helper.Get256ByteArray(ReadOnlySpan<byte>.Empty), output.AsSpan(0, 32).ToArray());
    }

    [Fact]
    public void KeccakSpongeValidatesParameters()
    {
        foreach (var bits in new[] { 0, 100, 255, 1600 })
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => { _ = new KeccakSpongeStruct(bits, new ulong[KeccakSpongeStruct.StateLength]); });
            Assert.Throws<ArgumentOutOfRangeException>(() => { _ = new KeccakSpongeStruct(bits, new ulong[KeccakSpongeStruct.StateLength], 0); });
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => { _ = new KeccakSpongeStruct(256, new ulong[KeccakSpongeStruct.StateLength - 1]); });
        Assert.Throws<ArgumentOutOfRangeException>(() => { _ = new KeccakSpongeStruct(256, new ulong[KeccakSpongeStruct.StateLength - 1], 0); });
    }

    [Theory]
    [MemberData(nameof(Sha3_224Vectors))]
    public void Sha3_224MatchesKnownAnswers(string message, int repeat, string expectedHex)
    {
        var input = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(message, repeat)));
        var expected = Convert.FromHexString(expectedHex);

        // The 224-bit mode is reachable through a Sha3 subclass; it has a 144-byte rate.
        var sha3 = new Sha3_224();
        sha3.HashBytes.Is(28u);
        Assert.Equal(expected, sha3.GetHash(input));
        foreach (var chunk in new[] { 1, 7, 143, 144, 145 })
        {
            if (chunk == 1 && input.Length > 1000)
            {// Keep the test fast.
                continue;
            }

            sha3.HashInitialize();
            for (var i = 0; i < input.Length; i += chunk)
            {
                sha3.HashUpdate(input.AsSpan(i, Math.Min(chunk, input.Length - i)));
            }

            Assert.Equal(expected, sha3.HashFinal());
        }

        Span<ulong> state = stackalloc ulong[KeccakSpongeStruct.StateLength];
        var sponge = new KeccakSpongeStruct(224, state);
        sponge.Absorb(input);
        var output = new byte[28];
        sponge.SqueezeTo(output);
        Assert.Equal(expected, output);
    }

    [Fact]
    public void Sha3SubclassDefaults()
    {
        var sha3 = new Sha3Default();
        sha3.HashName.Is("SHA3 Wrapper");
        sha3.HashBits.Is(0u);
        sha3.HashBytes.Is(0u);
        sha3.IsCryptographic.IsFalse();
        Assert.Throws<ArgumentOutOfRangeException>(() => sha3.GetHash("abc"u8));
    }

    private static void AssertSpan(byte[] expected, ReadOnlySpan<byte> input, SpanHash hash)
    {
        // The output may be longer than the hash; the trailing bytes must stay unchanged.
        var output = new byte[expected.Length + 3];
        Array.Fill(output, (byte)0xA5);
        hash(input, output);
        Assert.Equal(expected, output.AsSpan(0, expected.Length).ToArray());
        Assert.All(output.AsSpan(expected.Length).ToArray(), x => x.Is((byte)0xA5));
    }

    private static byte[] ToBytes(params ulong[] words) => MemoryMarshal.AsBytes(words.AsSpan()).ToArray();

    private sealed class Sha3_224 : Sha3
    {
        public override uint HashBits => 224;
    }

    private sealed class Sha3Default : Sha3
    {
    }
}
