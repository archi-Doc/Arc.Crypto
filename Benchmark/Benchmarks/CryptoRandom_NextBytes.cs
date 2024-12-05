// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CryptoRandom_NextBytes
{
    [Params(8, 16, 256)]
    public int Length { get; set; }

    private readonly Xoshiro256StarStar xo = new(12);
    private readonly byte[] random = new byte[256];

    public CryptoRandom_NextBytes()
    {
    }

    [Benchmark]
    public byte[] NextBytes_Xoshiro256()
    {
        this.xo.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_Rng()
    {
        RandomNumberGenerator.Fill(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_RandomVault_Xoshiro()
    {
        RandomVault.Xoshiro.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_RandomVaultObs_Xoshiro()
    {
        RandomVaultObsolete.Xoshiro.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_RandomVault_Aegis()
    {
        RandomVault.Aegis.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_RandomVaultObs_Aegis()
    {
        RandomVaultObsolete.Aegis.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_RandomVault_Rng()
    {
        RandomVault.RandomNumberGenerator.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] NextBytes_RandomVaultObs_Rng()
    {
        RandomVaultObsolete.RandomNumberGenerator.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }
}
