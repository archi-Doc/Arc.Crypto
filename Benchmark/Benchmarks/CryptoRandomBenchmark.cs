// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CryptoRandomBenchmark
{
    [Params(8, 16, 256)]
    // [Params(8)]
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
        // this.SpinWait();
        this.xo.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] Rng_Fill()
    {
        // this.SpinWait();
        RandomNumberGenerator.Fill(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] Rng_GetBytes()
    {
        // this.SpinWait();
        this.rng.GetBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] CryptoRandom_NextBytes()
    {
        // this.SpinWait();
        CryptoRandom.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVaultCrypto_NextBytes()
    {
        // this.SpinWait();
        RandomVault.Crypto.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVault2Crypto_NextBytes()
    {
        // this.SpinWait();
        RandomVault2.Crypto.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] RandomVaultPseudo_NextBytes()
    {
        // this.SpinWait();
        RandomVault.Pseudo.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    /*private void SpinWait()
    {
        Thread.SpinWait(10);
    }*/
}
