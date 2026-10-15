// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Arc.Collections;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Sha2HelperTest
{
    private delegate void SpanHash(ReadOnlySpan<byte> input, Span<byte> output);

    [Fact]
    public void MatchesSystemImplementation()
    {
        var data = new byte[4097];
        new Xoshiro256StarStar(21).NextBytes(data);

        // Lengths around the SHA-256 (64-byte) and SHA-512 (128-byte) block and padding boundaries.
        foreach (var length in new[] { 0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000, 4097 })
        {
            var input = data.AsSpan(0, length);
            var expected256 = SHA256.HashData(input);
            var expected384 = SHA384.HashData(input);
            var expected512 = SHA512.HashData(input);

            Assert.Equal(expected256, Sha2Helper.Get256ByteArray(input));
            Assert.Equal(expected384, Sha2Helper.Get384ByteArray(input));
            Assert.Equal(expected512, Sha2Helper.Get512ByteArray(input));

            AssertSpan(expected256, input, Sha2Helper.Get256Span);
            AssertSpan(expected384, input, Sha2Helper.Get384Span);
            AssertSpan(expected512, input, Sha2Helper.Get512Span);
            AssertSpan(expected512, input, Sha2Helper.Get512SpanLibsodium);

            var w256 = Sha2Helper.Get256UInt64(input);
            Assert.Equal(expected256, ToBytes(w256.Hash0, w256.Hash1, w256.Hash2, w256.Hash3));
            var w384 = Sha2Helper.Get384UInt64(input);
            Assert.Equal(expected384, ToBytes(w384.Hash0, w384.Hash1, w384.Hash2, w384.Hash3, w384.Hash4, w384.Hash5));
            var w512 = Sha2Helper.Get512UInt64(input);
            Assert.Equal(expected512, ToBytes(w512.Hash0, w512.Hash1, w512.Hash2, w512.Hash3, w512.Hash4, w512.Hash5, w512.Hash6, w512.Hash7));
        }
    }

    [Fact]
    public void IncrementalPoolsProduceExpectedAlgorithms()
    {
        var data = new byte[3000];
        new Xoshiro256StarStar(22).NextBytes(data);
        AssertPool(Sha2Helper.IncrementalSha256Pool, HashAlgorithmName.SHA256, SHA256.HashData(data), data);
        AssertPool(Sha2Helper.IncrementalSha512Pool, HashAlgorithmName.SHA512, SHA512.HashData(data), data);
    }

    [Fact]
    public void HelpersAreThreadSafe()
    {
        // The helpers and the SHA1 wrapper share static pools; every result is checked against a BCL one-shot.
        Parallel.For(0, 16, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount * 2, }, i =>
        {
            var random = new Xoshiro256StarStar((ulong)i + 100);
            var buffer = new byte[600];
            using var sha1 = new Arc.Crypto.Sha1();
            for (var n = 0; n < 200; n++)
            {
                var input = buffer.AsSpan(0, random.NextInt32(0, buffer.Length + 1));
                random.NextBytes(input);
                Assert.Equal(SHA256.HashData(input), Sha2Helper.Get256ByteArray(input));
                Assert.Equal(SHA512.HashData(input), Sha2Helper.Get512ByteArray(input));
                Assert.Equal(SHA1.HashData(input), sha1.GetHash(input));
            }
        });
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

    private static void AssertPool(ObjectPool<IncrementalHash> pool, HashAlgorithmName name, byte[] expected, byte[] data)
    {
        // The second round checks that an instance returned after GetHashAndReset is clean.
        for (var round = 0; round < 2; round++)
        {
            var hash = pool.Rent();
            hash.AlgorithmName.Is(name);
            hash.AppendData(data.AsSpan(0, 1000));
            hash.AppendData(data.AsSpan(1000));
            Assert.Equal(expected, hash.GetHashAndReset());
            pool.Return(hash);
        }
    }

    private static byte[] ToBytes(params ulong[] words) => MemoryMarshal.AsBytes(words.AsSpan()).ToArray();
}
