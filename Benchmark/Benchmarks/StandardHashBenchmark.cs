// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1310 // Field names should not contain underscore

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class StandardHashBenchmark
{
    private const int N = 1_000;
    private readonly byte[] data;
    private readonly HashAlgorithm sha256 = SHA256.Create();
    private readonly Sha3_256 sha3_256 = new();
    private readonly Sha3_384 sha3_384 = new();
    private readonly Sha3_512 sha3_512 = new();
    private readonly byte[] hash64;

    public StandardHashBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);
        this.hash64 = new byte[64];
    }

    // [Params(64, 200, 1_000)]
    [Params(1_000)]
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
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) Sha2_256Helper() => Sha2Helper.Get256_UInt64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public byte[] Sha2_512Helper()
    {
        Sha2Helper.Get512_Span(this.data.AsSpan(0, this.Length), this.hash64);
        return this.hash64;
    }

    [Benchmark]
    public byte[] Sha2_512Libsodium()
    {
        Sha2Helper.Get512_Libsodium(this.data.AsSpan(0, this.Length), this.hash64);
        return this.hash64;
    }

    [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) Sha3Helper_256() => Sha3Helper.Get256_UInt64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3, ulong Hash4, ulong Hash5, ulong Hash6, ulong Hash7) Sha3Helper_512() => Sha3Helper.Get512_UInt64(this.data.AsSpan(0, this.Length));

    [Benchmark]
    public byte Blake2B_256()
    {
        Span<byte> hash = stackalloc byte[32];
        Blake2B.Get256_Span(this.data.AsSpan(0, this.Length), hash);
        return hash[0];
    }

    [Benchmark]
    public byte Blake2B_512()
    {
        Span<byte> hash = stackalloc byte[64];
        Blake2B.Get512_Span(this.data.AsSpan(0, this.Length), hash);
        return hash[0];
    }

    [Benchmark]
    public byte Blake3_256()
    {
        Span<byte> hash = stackalloc byte[32];
        Blake3.Get256_Span(this.data.AsSpan(0, this.Length), hash);
        return hash[0];
    }

    [Benchmark]
    public byte Blake3Hasher_256()
    {
        using var hasher = Blake3Hasher.New();
        var half = this.Length / 2;
        hasher.Update(this.data.AsSpan(0, half));
        hasher.Update(this.data.AsSpan(half, this.Length - half));
        Span<byte> hash = stackalloc byte[32];
        hasher.Finalize(hash);
        return hash[0];
    }
}
