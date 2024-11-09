// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CryptoRandomBenchmark
{
    public const int Length = 32; // SeedKey

    private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();
    private readonly Xoshiro256StarStar xo = new(12);
    private readonly byte[] random = new byte[Length];

    public CryptoRandomBenchmark()
    {
    }

    [Benchmark]
    public byte[] Xoshiro256()
    {
        this.xo.NextBytes(this.random);
        return this.random;
    }

    [Benchmark]
    public byte[] Rng_Fill()
    {
        RandomNumberGenerator.Fill(this.random);
        return this.random;
    }

    [Benchmark]
    public byte[] Rng_GetBytes()
    {
        this.rng.GetBytes(this.random);
        return this.random;
    }

    [Benchmark]
    public byte[] RandomBytes()
    {
        CryptoSign.RandomBytes(this.random);
        return this.random;
    }

    [Benchmark]
    public byte[] RandomUInt32_8()
    {
        var b = this.random.AsSpan();
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());
        b = b.Slice(4);
        MemoryMarshal.Write(b, CryptoSign.RandomUInt32());

        return this.random;
    }
}
