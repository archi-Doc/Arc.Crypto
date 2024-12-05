// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class RandomNumberGeneratorBenchmark
{
    [Params(8, 16, 256, 1024, 4096)]
    public int Length { get; set; }

    private readonly byte[] random = new byte[4096];

    public RandomNumberGeneratorBenchmark()
    {
    }

    [Benchmark]
    public byte[] Rng_Fill()
    {
        RandomNumberGenerator.Fill(this.random.AsSpan(0, this.Length));
        return this.random;
    }
}
