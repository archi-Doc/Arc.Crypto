// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Base32ImplBenchmark
{
    private int n;

    public Base32ImplBenchmark()
    {
        this.n = 111;
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public int Mod5()
        => this.n % 5;

    [Benchmark]
    public int FastMod5()
        => Base32Sort.FastMod5(this.n);

    [Benchmark]
    public int GetEncodedLength()
    {
        var bits = this.n * 8;
        var count = (bits / 5) + (Base32Sort.FastMod5(bits) == 0 ? 0 : 1);
        return count;
    }

    [Benchmark]
    public int GetEncodedLength2()
        => ((this.n << 3) + 4) / 5;
}
