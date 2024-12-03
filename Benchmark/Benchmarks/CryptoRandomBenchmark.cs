// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CryptoRandomBenchmark
{
    [Params(8, 16, 256)]
    // [Params(256)]
    public int Length { get; set; }

    private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
    private readonly Xoshiro256StarStar xo = new(12);
    private readonly byte[] random = new byte[256];

    public CryptoRandomBenchmark()
    {
    }

    [Benchmark]
    public byte[] Xoshiro256()
    {
        this.xo.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] Rng_Fill()
    {
        RandomNumberGenerator.Fill(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] CryptoRandom_NextBytes()
    {
        CryptoRandom.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVault_Pseudo_NextBytes()
    {
        RandomVault.Xoshiro.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVault_Aegis_NextBytes()
    {
        RandomVault.Aegis.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVault_Libsodium_NextBytes()
    {
        RandomVault.Libsodium.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVault_Rng_NextBytes()
    {
        RandomVault.RandomNumberGenerator.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }
}
