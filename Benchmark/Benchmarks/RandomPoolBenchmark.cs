// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arc.Crypto;
using Benchmark.Design;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1405 // Debug.Assert should provide message text

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class RandomPoolBenchmark
{
    public static void Test1()
    {
        var mt = new MersenneTwister(new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL });
        var poolLock = new RandomPoolLock(() => mt.NextULong());
        Debug.Assert(poolLock.NextULong() == 7266447313870364031UL);

        for (var i = 0; i < 20000; i++)
        {
            poolLock.NextULong();
        }

        mt.Reset(new ulong[] { 0x12345UL, 0x23456UL, 0x34567UL, 0x45678UL });
        var poolSliding = new RandomPoolSliding(() => mt.NextULong());
        Debug.Assert(poolSliding.NextULong() == 7266447313870364031UL);

        for (var i = 0; i < 20000; i++)
        {
            poolSliding.NextULong();
        }
    }

    public MersenneTwister Mt { get; set; } = new(42);

    internal RandomPoolLock PoolLock { get; set; }

    internal RandomPoolSliding PoolSliding { get; set; }

    public RandomPoolBenchmark()
    {
        this.PoolLock = new(() => this.Mt.NextULong());
        this.PoolSliding = new(() => this.Mt.NextULong());
    }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public ulong Raw()
    {
        return this.Mt.NextULong();
    }

    [Benchmark]
    public ulong Lock()
    {
        lock (this.Mt)
        {
            return this.Mt.NextULong();
        }
    }

    [Benchmark]
    public ulong Pool_Sliding()
    {
        return this.PoolSliding.NextULong();
    }
}
