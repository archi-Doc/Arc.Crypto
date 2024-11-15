// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Sha256Benchmark
{// measure the time to calculate a hash of 1 MB data. Sha256/Managed/ServiceProvider.
    private const int N = 1_000_000;
    private readonly byte[] data;

    private readonly HashAlgorithm sha256;
    // private readonly HashAlgorithm sha256Managed;
    // private readonly HashAlgorithm sha256ServiceProvider;
    private readonly IncrementalHash incrementalHash;

    public Sha256Benchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);

        this.sha256 = System.Security.Cryptography.SHA256.Create();
#pragma warning disable SYSLIB0021 // Type or member is obsolete
        // this.sha256Managed = System.Security.Cryptography.SHA256Managed.Create();
        // this.sha256ServiceProvider = new SHA256CryptoServiceProvider();
#pragma warning restore SYSLIB0021 // Type or member is obsolete

        this.incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    }

    // [Params(10, 1_000, 1_000_000)]
    [Params(1_000)]
    public int Length { get; set; }

    [Benchmark]
    public byte[] Sha256() => this.sha256.ComputeHash(this.data, 0, this.Length);

    [Benchmark]
    public byte[] Sha256B() => Sha2Helper.Get256_ByteArray(this.data.AsSpan(0, this.Length));

    /*[Benchmark]
    public byte[] Sha256Managed() => this.sha256Managed.ComputeHash(this.data, 0, this.Length);

    [Benchmark]
    public byte[] Sha256ServiceProvider() => this.sha256ServiceProvider.ComputeHash(this.data, 0, this.Length);*/

    [Benchmark]
    public byte[] Sha256Incremental()
    {
        this.incrementalHash.AppendData(this.data.AsSpan(0, this.Length));
        return this.incrementalHash.GetHashAndReset();
    }

    [Benchmark]
    public byte[] Sha256Incremental2()
    {
        var n = this.Length >> 1;
        this.incrementalHash.AppendData(this.data.AsSpan(0, n));
        this.incrementalHash.AppendData(this.data.AsSpan(n, this.Length - n));
        return this.incrementalHash.GetHashAndReset();
    }

    [Benchmark]
    public byte[] Sha256Incremental3()
    {
        var incrementalHash = Sha2Helper.IncrementalSha256Pool.Rent();
        try
        {
            incrementalHash.AppendData(this.data.AsSpan(0, this.Length));
            return incrementalHash.GetHashAndReset();
        }
        finally
        {
            Sha2Helper.IncrementalSha256Pool.Return(incrementalHash);
        }
    }
}
