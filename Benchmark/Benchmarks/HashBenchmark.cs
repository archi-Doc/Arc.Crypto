// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class HashBenchmark
{
    private const int N = 1_000_000;
    private readonly byte[] data;
    private FarmHash farm;
    private XXHash32 xxh32;
    private XxHash64 xxh64;

    public HashBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);
        this.farm = new FarmHash();
        this.xxh32 = new XXHash32();
        this.xxh64 = new XxHash64();
    }

    [Params(10, 100, 200, 1000, 1_000_000)]
    public int Length { get; set; }

    [Benchmark]
    public ulong ArcFarmHash32() => Arc.Crypto.FarmHash.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcFarmHash64() => Arc.Crypto.FarmHash.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public uint ArcXXHash32() => Arc.Crypto.XXHash32.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcXxHash64() => Arc.Crypto.XxHash64.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcXxHash3() => Arc.Crypto.XxHash3.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong XxHash3() => System.IO.Hashing.XxHash3.HashToUInt64(this.data.AsSpan(0, this.Length));

    /*// [Benchmark]
    public byte[] ArcXXHash32_IHash()
    {
        this.xxh32.HashInitialize();
        this.xxh32.HashUpdate(this.data.AsSpan(0, this.Length));
        return this.xxh32.HashFinal();
    }

    [Benchmark]
    public byte[] ArcXxHash64_IHash()
    {
        this.xxh64.HashInitialize();
        this.xxh64.HashUpdate(this.data.AsSpan(0, this.Length));
        return this.xxh64.HashFinal();
    }

    [Benchmark]
    public byte[] ArcFarmHash64_IHash()
    {
        this.farm.HashInitialize();
        this.farm.HashUpdate(this.data.AsSpan(0, this.Length));
        return this.farm.HashFinal();
    }

    [Benchmark]
    public ulong ArcAdler32() => Arc.Crypto.Adler32.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcCrc32() => Arc.Crypto.Crc32.Hash32(this.data.AsSpan(0, this.Length));*/
}
