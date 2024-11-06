// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1310 // Field names should not contain underscore

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class SpeedBenchmark
{// measure the time to calculate a hash of 1 MB data.
    private const int N = 1_000_000;
    private readonly byte[] data;
    private IHash farm;
    private IHash farmBeta;
    private IHash xxh32;
    private IHash xxh64;
    private IHash sha1;
    private IHash sha2_256;
    private IHash sha2_384;
    private IHash sha2_512;
    private IHash sha3_256;
    private IHash sha3_256ob;
    private IHash sha3_384;
    private IHash sha3_512;

    public SpeedBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);

        this.farm = new FarmHash();
        this.farmBeta = new Beta.Crypto.FarmHash(); // System.Numerics.BitOperation
        this.xxh32 = new XXHash32();
        this.xxh64 = new XxHash64();
        this.sha1 = new Arc.Crypto.Sha1();
        this.sha2_256 = new Sha2_256();
        this.sha2_384 = new Sha2_384();
        this.sha2_512 = new Sha2_512();
        this.sha3_256 = new Sha3_256();
        this.sha3_256ob = new Obsolete.Sha3_256();
        this.sha3_384 = new Sha3_384();
        this.sha3_512 = new Sha3_512();
    }

    [Benchmark]
    public byte[] FarmHash64() => this.farm.GetHash(this.data);

    /*[Benchmark]
    public byte[] FarmHash64Beta() => this.farmBeta.GetHash(this.data);

    [Benchmark]
    public byte[] XxHash32() => this.xxh32.GetHash(this.data);

    [Benchmark]
    public byte[] XxHash64() => this.xxh64.GetHash(this.data);

    [Benchmark]
    public byte[] Sha1() => this.sha1.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] ShaA2_256() => this.sha2_256.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha2_384() => this.sha2_384.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha2_512() => this.sha2_512.GetHash(this.data, 0, this.data.Length);*/

    // [Benchmark]
    public byte[] Sha3_256() => this.sha3_256.GetHash(this.data, 0, this.data.Length);

    // [Benchmark]
    public byte[] Sha3_256Ob() => this.sha3_256ob.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Blake2B_256()
    {
        return Blake2BHelper.Get256_ByteArray(this.data.AsSpan(0, this.data.Length));
    }

    /*[Benchmark]
    public byte[] Sha3_384() => this.sha3_384.GetHash(this.data, 0, this.data.Length);

    [Benchmark]
    public byte[] Sha3_512() => this.sha3_512.GetHash(this.data, 0, this.data.Length);*/
}
