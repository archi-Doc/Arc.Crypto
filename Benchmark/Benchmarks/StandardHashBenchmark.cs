// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1310 // Field names should not contain underscore

namespace Benchmark.Benchmarks;

[Config(typeof(BenchmarkConfig))]
public class StandardHashBenchmark
{
    private const int N = 1_000;
    private readonly byte[] data;
    private readonly HashAlgorithm sha256 = SHA256.Create();
    private readonly Sha3_256 sha3_256 = new();
    private readonly Sha3_384 sha3_384 = new();
    private readonly Sha3_512 sha3_512 = new();

    public StandardHashBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);
    }

    [Params(10, 100, 1_000)]
    public int Length { get; set; }

    /*[Benchmark]
    public ulong ArcFarmHash32() => Arc.Crypto.FarmHash.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcFarmHash64() => Arc.Crypto.FarmHash.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public uint ArcXXHash32() => Arc.Crypto.XXHash32.Hash32(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public ulong ArcXxHash64() => Arc.Crypto.XxHash64.Hash64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public byte[] Sha256() => this.sha256.ComputeHash(this.data, 0, this.Length);*/

    [Benchmark]
    public byte[] Sha3_256() => this.sha3_256.GetHash(this.data.AsSpan(0, this.Length));

    // [Benchmark]
    public byte[] Sha3_384() => this.sha3_384.GetHash(this.data.AsSpan(0, this.Length));

    // [Benchmark]
    public byte[] Sha3_512() => this.sha3_512.GetHash(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) Sha3Struct_256() => Sha3Struct.Get256_UInt64(this.data.AsSpan(0, this.Length));

    // [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3, ulong Hash4, ulong Hash5) Sha3Struct_384() => Sha3Struct.Get384_UInt64(this.data.AsSpan(0, this.Length));

    // [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3, ulong Hash4, ulong Hash5, ulong Hash6, ulong Hash7) Sha3Struct_5126() => Sha3Struct.Get512_UInt64(this.data.AsSpan(0, this.Length));
}
