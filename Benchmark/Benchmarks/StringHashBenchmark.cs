// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

#pragma warning disable CS0414
#pragma warning disable SA1306 // Field names should begin with lower-case letter

[Config(typeof(BenchmarkConfig))]
public class StringHashBenchmark
{
    private string String3 = "ABC";
    private string String40 = "Benchmark.Benchmarks.StringHashBenchmark";
    private string String80 = "Benchmark.Benchmarks.StringHashBenchmark";
    private string String40A = "Benchmark.Benchmarks";
    private string String40B = ".StringHashBenchmark";
    private string String200 = "Benchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmark";

    public StringHashBenchmark()
    {
    }

    [Benchmark]
    public ulong String3_FarmHash64() => Arc.Crypto.FarmHash.Hash64(this.String3);

    [Benchmark]
    public ulong String3_XxHash3() => Arc.Crypto.XxHash3.Hash64(this.String3);

    [Benchmark]
    public ulong String3_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(this.String3);

    [Benchmark]
    public ulong String40_FarmHash64() => Arc.Crypto.FarmHash.Hash64(this.String40);

    [Benchmark]
    public ulong String40_XxHash3() => Arc.Crypto.XxHash3.Hash64(this.String40);

    [Benchmark]
    public ulong String40_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(this.String40);

    [Benchmark]
    public ulong String80_FarmHash64() => Arc.Crypto.FarmHash.Hash64(this.String80);

    [Benchmark]
    public ulong String80_XxHash3() => Arc.Crypto.XxHash3.Hash64(this.String80);

    [Benchmark]
    public ulong String80_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(this.String80);

    [Benchmark]
    public ulong String80_FarmHash2_64() => Arc.Crypto.FarmHash2.Hash64(this.String80);

    [Benchmark]
    public ulong String40x2_FarmHash_64()
    {
        var farm = default(FarmHash);
        farm.Append(this.String40A);
        farm.Append(this.String40B);
        return farm.Finalize();
    }

    [Benchmark]
    public ulong String40x2_FarmHash2_64()
    {
        var farm = default(FarmHash2);
        farm.Append(this.String40A);
        farm.Append(this.String40B);
        return farm.Finalize();
    }

    [Benchmark]
    public ulong String40x100_FarmHash_64()
    {
        var farm = default(FarmHash);
        farm.Append(this.String40A);
        for (var i = 0; i < 100; i++)
        {
            farm.Append(this.String40B);
        }

        return farm.Finalize();
    }

    [Benchmark]
    public ulong String40x100_FarmHash2_64()
    {
        var farm = default(FarmHash2);
        farm.Append(this.String40A);
        for (var i = 0; i < 100; i++)
        {
            farm.Append(this.String40B);
        }

        return farm.Finalize();
    }

    [Benchmark]
    public ulong String200_FarmHash64() => Arc.Crypto.FarmHash.Hash64(this.String200);

    [Benchmark]
    public ulong String200_XxHash3() => Arc.Crypto.XxHash3.Hash64(this.String200);

    [Benchmark]
    public ulong String200_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(this.String200);
}
