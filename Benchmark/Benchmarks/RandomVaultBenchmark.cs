// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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
        var poolSliding = new RandomVault(() => mt2.NextULong(), x => mt2.NextBytes(x));
        Debug.Assert(poolSliding.NextULong() == 7266447313870364031UL);

        for (var i = 0; i < 20000; i++)
        {
            poolSliding.NextULong();
        }

        var mt3 = new MersenneTwister(new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL });
        var poolConcurrentQueue = new RandomPoolConcurrentQueue(() => mt3.NextULong(), x => mt3.NextBytes(x));
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
        this.PoolLock = new(() => this.Mt.NextULong());
        this.Vault = new(() => this.Mt.NextULong(), x => this.Mt.NextBytes(x));
        this.PoolSplit = new(() => this.Mt.NextULong());
        this.PoolConcurrentQueue = new(() => this.Mt.NextULong(), x => this.Mt.NextBytes(x));

        var mt = new MersenneTwister(42);
        this.Vault2 = new(() => mt.NextULong(), x => mt.NextBytes(x), 2_000_000);

        this.RngVault = new(null, x => RandomNumberGenerator.Fill(x), 2_000_000);
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
            return this.Mt.NextULong();
        }
    }

    [Benchmark]
    public ulong Mt_Vault()
    {
        return this.Vault.NextULong();
    }

    [IterationSetup(Target = "Mt_Vault2")]
    public void SetupMt_Vault2()
    {
        this.Vault2.Generate().Wait();
    }

    [Benchmark]
    [InvocationCount(1_000_000)]
    public ulong Mt_Vault2()
    {
        return this.Vault2.NextULong();
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

    [IterationSetup(Target = "Rng_Vault")]
    public void SetupRng_Vault()
    {
        this.RngVault.Generate().Wait();
    }

    [Benchmark]
    [InvocationCount(1_000_000)]
    public ulong Rng_Vault()
    {
        return this.RngVault.NextULong();
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
