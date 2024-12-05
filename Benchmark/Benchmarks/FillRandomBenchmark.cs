// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using Arc.Crypto.Random;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class FillRandomBenchmark
{
    [Params(8, 16, 256, 1024, 4096)]
    public int Length { get; set; }

    private readonly byte[] random = new byte[4096];
    private readonly AegisRandom aegis;

    public FillRandomBenchmark()
    {
        this.aegis = new();
    }

    [Benchmark]
    public byte[] Rng_Fill()
    {
        RandomNumberGenerator.Fill(this.random.AsSpan(0, this.Length));
        return this.random;
    }

    [Benchmark]
    public byte[] Aegis_Fill()
    {
        this.aegis.NextBytes(this.random.AsSpan(0, this.Length));
        return this.random;
    }
}
