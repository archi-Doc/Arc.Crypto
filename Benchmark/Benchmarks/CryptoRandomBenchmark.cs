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
    public byte[] RandomVaultPseudo_NextBytes()
    {
        RandomVault.Pseudo.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVaultAegis_NextBytes()
    {
        RandomVault.Crypto.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVaultLibsodium_NextBytes()
    {
        RandomVault.Libsodium.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVaultRng_NextBytes()
    {
        RandomVault.RandomNumberGenerator.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }
}
