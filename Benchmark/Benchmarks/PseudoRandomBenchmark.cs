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
    public Random Random { get; set; } = new();

    public MersenneTwister Mt { get; set; } = new(42);

    public Xoshiro256StarStar Xo { get; set; } = new();

    public ObjectPool<Random> Pool { get; set; } = new(() => new Random());

    public byte[] RandomBytes { get; } = new byte[24];

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
    public int Random_Int()
    {
        return this.Random.Next();
    }

    [Benchmark]
    public int MT_Int()
    {
        return this.Mt.NextInt();
    }

    [Benchmark]
    public int Xo_Int()
    {
        return this.Xo.NextInt();
    }

    [Benchmark]
    public ulong MT_ULong()
    {
        return this.Mt.NextULong();
    }

    [Benchmark]
    public ulong Xo_ULong()
    {
        return this.Xo.NextULong();
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
    public double Xo_Double()
    {
        return this.Xo.NextDouble();
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
    public double Xo_Range()
    {
        return this.Xo.NextInt(int.MinValue, int.MaxValue);
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

    [Benchmark]
    public byte[] Xo_Bytes()
    {
        this.Xo.NextBytes(this.RandomBytes);
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
