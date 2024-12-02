// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using Arc.Crypto;
using Benchmark.Design;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1405 // Debug.Assert should provide message text

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class RandomVaultBenchmark
{
    public static void Test1()
    {
        var mt2 = new MersenneTwister(new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL });
        var poolSliding = new RandomVault(x => mt2.NextBytes(x), false);
        Debug.Assert(poolSliding.NextUInt64() == 7266447313870364031UL);

        for (var i = 0; i < 20000; i++)
        {
            poolSliding.NextUInt64();
        }

        var mt3 = new MersenneTwister(new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL });
        var poolConcurrentQueue = new RandomPoolConcurrentQueue(() => mt3.NextUInt64(), x => mt3.NextBytes(x));
        Debug.Assert(poolConcurrentQueue.NextULong() == 7266447313870364031UL);

        for (var i = 0; i < 20000; i++)
        {
            poolConcurrentQueue.NextULong();
        }
    }

    public MersenneTwister Mt { get; set; } = new(42);

    internal RandomPoolLock PoolLock { get; set; }

    internal RandomVault Vault { get; set; }

    internal RandomVault Vault2 { get; set; }

    internal RandomVault RngVault { get; set; }

    internal RandomPoolSplit PoolSplit { get; set; }

    internal RandomPoolConcurrentQueue PoolConcurrentQueue { get; set; }

    public RandomVaultBenchmark()
    {
        this.PoolLock = new(() => this.Mt.NextUInt64());
        this.Vault = new(x => this.Mt.NextBytes(x), false);
        this.PoolSplit = new(() => this.Mt.NextUInt64());
        this.PoolConcurrentQueue = new(() => this.Mt.NextUInt64(), x => this.Mt.NextBytes(x));

        var mt = new MersenneTwister(42);
        this.Vault2 = new(x => mt.NextBytes(x), false);

        this.RngVault = new(x => RandomNumberGenerator.Fill(x), true);
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    /*[Benchmark]
    public ulong Raw()
    {
        return this.Mt.NextULong();
    }*/

    [Benchmark]
    public ulong Lock()
    {
        lock (this.Mt)
        {
            return this.Mt.NextUInt64();
        }
    }

    [Benchmark]
    public ulong Mt_Vault()
    {
        return this.Vault.NextUInt64();
    }

    [Benchmark]
    [InvocationCount(1_000_000)]
    public ulong Mt_Vault2()
    {
        return this.Vault2.NextUInt64();
    }

    [Benchmark]
    public ulong Pool_ConcurrentQueue()
    {
        return this.PoolConcurrentQueue.NextULong();
    }

    [IterationSetup(Target = "Pool_ConcurrentQueue2")]
    public void SetupConcurrentQueue()
    {
        this.PoolConcurrentQueue.Clear();
        this.PoolConcurrentQueue.Generate(1_000_000).Wait();
    }

    [Benchmark]
    [InvocationCount(1_000_000)]
    public ulong Pool_ConcurrentQueue2()
    {
        return this.PoolConcurrentQueue.NextULong();
    }

    [Benchmark]
    [InvocationCount(1_000_000)]
    public ulong Rng_Vault()
    {
        return this.RngVault.NextUInt64();
    }

    [Benchmark]
    public unsafe ulong Rng_Rng()
    {
        ulong u;
        Span<byte> b = stackalloc byte[8];
        RandomNumberGenerator.Fill(b);
        fixed (byte* bp = b)
        {
            u = *(ulong*)bp;
        }

        return u;
    }

    [Benchmark]
    public unsafe ulong Rng_Rng2()
    {
        Span<byte> b = stackalloc byte[8];
        RandomNumberGenerator.Fill(b);
        return BitConverter.ToUInt64(b);
    }

    /*[Benchmark]
    public ulong Pool_Split()
    {
        return this.PoolSplit.NextULong();
    }*/
}
