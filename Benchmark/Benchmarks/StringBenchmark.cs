// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class StringBenchmark
{// measure the time to calculate a hash of the string.
    private const string TestString = "0123456789ABCDEF0123456789ABCDEF";

    [Benchmark]
    public int String_GetHashCode() => TestString.GetHashCode();

    [Benchmark]
    public uint ArcFarmHash32_Direct() => Arc.Crypto.FarmHash.Hash32(TestString);

    [Benchmark]
    public uint ArcFarmHash32_64to32() => unchecked((uint)Arc.Crypto.FarmHash.Hash64(TestString));

    [Benchmark]
    public ulong ArcFarmHash64_Direct() => Arc.Crypto.FarmHash.Hash64(TestString);

    /*[Benchmark]
    public ulong ArcFarmHash64_GetBytes() => Arc.Crypto.FarmHash.Hash64(Encoding.UTF8.GetBytes(TestString));

    [Benchmark]
    public uint ArcXXHash32_Direct() => Arc.Crypto.XXHash32.Hash32(TestString);

    [Benchmark]
    public ulong ArcXxHash64_Direct() => Arc.Crypto.XxHash64.Hash64(TestString);*/
}
