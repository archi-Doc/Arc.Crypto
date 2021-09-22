// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class PseudoRandomBenchmark
{
    public Random Random { get; set; } = new(42);

    public MersenneTwister Mt { get; set; } = new(42);

    public ObjectPool<Random> Pool { get; set; } = new(() => new Random());

    public byte[] RandomBytes { get; } = new byte[43];

    public PseudoRandomBenchmark()
    {
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
    public int Random_Raw()
    {
        return this.Random.Next();
    }

    [Benchmark]
    public uint MT_Raw()
    {
        return this.Mt.NextUInt();
    }

    [Benchmark]
    public uint MT_Long()
    {
        return (uint)this.Mt.NextULong();
    }

    [Benchmark]
    public double Random_Double()
    {
        return this.Random.NextDouble();
    }

    [Benchmark]
    public double MT_Double()
    {
        return this.Mt.NextDouble();
    }

    [Benchmark]
    public double Random_Range()
    {
        return this.Random.Next(int.MinValue, int.MaxValue);
    }

    [Benchmark]
    public double MT_Range()
    {
        return this.Mt.NextInt(int.MinValue, int.MaxValue);
    }

    [Benchmark]
    public byte[] Random_Bytes()
    {
        this.Random.NextBytes(this.RandomBytes);
        return this.RandomBytes;
    }

    [Benchmark]
    public byte[] Mt_Bytes()
    {
        this.Mt.NextBytes(this.RandomBytes);
        return this.RandomBytes;
    }

    /*[Benchmark]
    public int Random_Lock()
    {
        lock (this.Random)
        {
            return this.Random.Next();
        }
    }

    [Benchmark]
    public int Random_ObjectPool()
    {
        var r = this.Pool.Get();
        try
        {
            return r.Next();
        }
        finally
        {
            this.Pool.Return(r);
        }
    }

    [Benchmark]
    public int Random_New()
    {
        var r = new Random(12);
        return r.Next();
    }*/
}
