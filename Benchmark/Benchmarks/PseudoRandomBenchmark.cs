// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class PseudoRandomBenchmark
{
    public Random Random { get; set; } = new();

    public MersenneTwister Mt { get; set; } = new(42);

    public Xoshiro256StarStar Xo { get; set; } = new();

    public Xoroshiro128StarStar Xo128 { get; set; } = new();

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

    /*[Benchmark]
    public int Random_Int()
    {
        return this.Random.Next();
    }

    [Benchmark]
    public int MT_Int()
    {
        return this.Mt.NextInt32();
    }

    [Benchmark]
    public int Xo_Int()
    {
        return this.Xo.NextInt32();
    }

    [Benchmark]
    public ulong MT_ULong()
    {
        return this.Mt.NextUInt64();
    }

    [Benchmark]
    public ulong Xo_ULong()
    {
        return this.Xo.NextUInt64();
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
        return this.Mt.NextInt32(int.MinValue, int.MaxValue);
    }

    [Benchmark]
    public double Xo_Range()
    {
        return this.Xo.NextInt32(int.MinValue, int.MaxValue);
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
    }*/

    [Benchmark]
    public ulong Xo_ULong10()
    {
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        this.Xo.NextUInt64();
        return this.Xo.NextUInt64();
    }

    [Benchmark]
    public ulong Xo128_ULong10()
    {
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        this.Xo128.NextUInt64();
        return this.Xo128.NextUInt64();
    }
}
