// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class StringHashBenchmark
{
    private const string String3 = "ABC";
    private const string String40 = "Benchmark.Benchmarks.StringHashBenchmark";
    private const string String80 = "Benchmark.Benchmarks.StringHashBenchmark";
    private const string String200 = "Benchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmarkBenchmark.Benchmarks.StringHashBenchmark";

    public StringHashBenchmark()
    {
    }

    [Benchmark]
    public ulong String3_FarmHash32() => Arc.Crypto.FarmHash.Hash32(String3);

    [Benchmark]
    public ulong String3_FarmHash64() => Arc.Crypto.FarmHash.Hash64(String3);

    [Benchmark]
    public ulong String3_XxHash3() => Arc.Crypto.XxHash3.Hash64(String3);

    [Benchmark]
    public ulong String3_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(String3);

    [Benchmark]
    public ulong String40_FarmHash32() => Arc.Crypto.FarmHash.Hash32(String40);

    [Benchmark]
    public ulong String40_FarmHash64() => Arc.Crypto.FarmHash.Hash64(String40);

    [Benchmark]
    public ulong String40_XxHash3() => Arc.Crypto.XxHash3.Hash64(String40);

    [Benchmark]
    public ulong String40_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(String40);

    [Benchmark]
    public ulong String80_FarmHash32() => Arc.Crypto.FarmHash.Hash32(String80);

    [Benchmark]
    public ulong String80_FarmHash64() => Arc.Crypto.FarmHash.Hash64(String80);

    [Benchmark]
    public ulong String80_XxHash3() => Arc.Crypto.XxHash3.Hash64(String80);

    [Benchmark]
    public ulong String80_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(String80);

    [Benchmark]
    public ulong String200_FarmHash32() => Arc.Crypto.FarmHash.Hash32(String200);

    [Benchmark]
    public ulong String200_FarmHash64() => Arc.Crypto.FarmHash.Hash64(String200);

    [Benchmark]
    public ulong String200_XxHash3() => Arc.Crypto.XxHash3.Hash64(String200);

    [Benchmark]
    public ulong String200_XxHash3Slim() => Arc.Collections.XxHash3Slim.Hash64(String200);
}
