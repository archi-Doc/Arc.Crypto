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
    public byte[] SHA3_256()
    {
        var h = new SHA3_256();
        return h.GetHash(this.ByteArray);
    }
}
