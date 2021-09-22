// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class CryptoRandomBenchmark
{
    public static void Test1()
    {
        var sw = new Stopwatch();
        var b = new byte[100_000_000];

        var mt = new MersenneTwister(42);
        sw.Restart();
        mt.NextBytes(b);
        Stop("MersenneTwister.NextBytes()");

        sw.Restart();
        RandomNumberGenerator.Fill(b);
        Stop("RandomNumberGenerator.Fill()");

        void Stop(string name)
        {
            sw.Stop();
            Console.WriteLine($"{name}: {sw.ElapsedMilliseconds} ms");
        }
    }

    public MersenneTwister Mt { get; set; } = new(42);

    public RandomNumberGenerator Rng { get; set; } = RandomNumberGenerator.Create();

    public byte[] RandomBytes { get; } = new byte[64];

    public CryptoRandomBenchmark()
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
    public byte[] Mt_Bytes()
    {// Pseudo-random
        lock (this.Mt)
        {
            this.Mt.NextBytes(this.RandomBytes);
            return this.RandomBytes;
        }
    }

    [Benchmark]
    public byte[] Rng_Fill()
    {
        RandomNumberGenerator.Fill(this.RandomBytes);
        return this.RandomBytes;
    }

    [Benchmark]
    public byte[] Rng_GetBytes()
    {
        this.Rng.GetBytes(this.RandomBytes);
        return this.RandomBytes;
    }

    [Benchmark]
    public ulong Mt_ULong()
    {// Pseudo-random
        lock (this.Mt)
        {
            return this.Mt.NextULong();
        }
    }

    [Benchmark]
    public ulong Rng_ULong()
    {
        Span<byte> b = stackalloc byte[8];
        RandomNumberGenerator.Fill(b);
        return BitConverter.ToUInt64(b);
    }

    [Benchmark]
    public ulong Rng_ULong2()
    {
        var a = (uint)RandomNumberGenerator.GetInt32(0xFFFFFF);
        var b = (uint)RandomNumberGenerator.GetInt32(0xFFFFFF);
        var c = (uint)RandomNumberGenerator.GetInt32(0xFFFFFF);
        return ((ulong)c << 24) ^ ((ulong)b << 12) ^ (ulong)a;
    }

    [Benchmark]
    public byte Rng_Byte()
    {
        Span<byte> b = stackalloc byte[1];
        RandomNumberGenerator.Fill(b);
        return b[0];
    }
}
