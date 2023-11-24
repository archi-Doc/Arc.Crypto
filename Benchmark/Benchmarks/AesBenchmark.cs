// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class AesBenchmark
{
    private Aes aes;
    private byte[] key;
    private byte[] iv;
    private byte[] source;
    private byte[] destination;

    public AesBenchmark()
    {
        this.aes = Aes.Create();
        this.aes.KeySize = 256;

        this.key = new byte[32];
        RandomVault.Pseudo.NextBytes(this.key);
        this.aes.Key = this.key;

        this.iv = new byte[16];
        RandomVault.Pseudo.NextBytes(this.iv);

        this.source = new byte[1000];
        RandomVault.Pseudo.NextBytes(this.source);

        this.destination = new byte[2000];
    }

    [Params(10, 100, 1000)]
    public int Length { get; set; }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public int TestAes()
    {
        this.aes.TryEncryptCbc(this.source.AsSpan(0, this.Length), this.iv, this.destination, out var written);
        return written;
    }

    [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) TestSha2()
    {
        return Sha2Helper.Get256_UInt64(this.source.AsSpan(0, this.Length));
    }

    [Benchmark]
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) TestSha3()
    {
        return Sha3Helper.Get256_UInt64(this.source.AsSpan(0, this.Length));
    }
}
