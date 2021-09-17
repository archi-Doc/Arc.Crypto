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
public class HashInstanceBenchmark
{
    public HashInstanceBenchmark()
    {
        this.ByteArray = new byte[this.Length];
        for (var i = 0; i < this.Length; i++)
        {
            this.ByteArray[i] = (byte)i;
        }
    }

    [Params(10)]
    public int Length { get; set; }

    public byte[] ByteArray { get; } = default!;

    public SHA3_256 SHA3Instance { get; } = new ();

    public Obsolete.SHA3_256 SHA3ObsoleteInstance { get; } = new ();

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public ulong Farmhash()
    {
        return FarmHash.Hash64(this.ByteArray);
    }

    [Benchmark]
    public byte[] SHA3()
    {
        var h = new SHA3_256();
        return h.GetHash(this.ByteArray);
    }

    [Benchmark]
    public (ulong h0, ulong h1, ulong h2, ulong h3) SHA3ULong()
    {
        var h = new SHA3_256();
        return h.GetHashULong(this.ByteArray);
    }

    [Benchmark]
    public byte[] SHA3_Obsolete()
    {
        var h = new Obsolete.SHA3_256();
        return h.GetHash(this.ByteArray);
    }

    /*[Benchmark]
    public byte[] SHA3_NoInstance()
    {
        return this.SHA3Instance.GetHash(this.ByteArray);
    }

    [Benchmark]
    public byte[] SHA3_Obsolete_NoInstance()
    {
        return this.SHA3ObsoleteInstance.GetHash(this.ByteArray);
    }*/
}
