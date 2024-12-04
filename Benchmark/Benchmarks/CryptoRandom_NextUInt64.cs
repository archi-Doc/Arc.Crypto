﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CryptoRandom_NextUInt64
{
    private readonly Xoshiro256StarStar xo = new(12);

    public CryptoRandom_NextUInt64()
    {
    }

    [Benchmark]
    public ulong NextUInt64_Xoshiro256()
        => this.xo.NextUInt64();

    [Benchmark]
    public ulong NextUInt64_RandomVault_Xoshiro256()
        => RandomVault.Xoshiro.NextUInt64();

    [Benchmark]
    public ulong NextUInt64_RandomVault2_Xoshiro256()
        => RandomVault2.Xoshiro.NextUInt64();

    [Benchmark]
    public ulong NextUInt64_RandomVault_Aegis()
        => RandomVault.Aegis.NextUInt64();

    [Benchmark]
    public ulong NextUInt64_RandomVault2_Aegis()
        => RandomVault2.Aegis.NextUInt64();

    [Benchmark]
    public ulong NextUInt64_RandomVault_Rng()
        => RandomVault.RandomNumberGenerator.NextUInt64();

    [Benchmark]
    public ulong NextUInt64_RandomVault2_Rng()
        => RandomVault2.RandomNumberGenerator.NextUInt64();
}
