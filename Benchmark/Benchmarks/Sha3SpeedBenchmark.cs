// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;

#pragma warning disable SA1310 // Field names should not contain underscore

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Sha3SpeedBenchmark
{// measure the time to calculate a hash of { data(N) x Repeat}.
    private const int N = 41;
    private const int Repeat = 1471;
    private readonly byte[] data;
    private IHash sha3_256;
    private IHash sha3_384;
    private IHash sha3_512;

    public Sha3SpeedBenchmark()
    {
        this.data = new byte[N];
        new Random(42).NextBytes(this.data);

        this.sha3_256 = new Sha3_256();
        this.sha3_384 = new Sha3_384();
        this.sha3_512 = new Sha3_512();
    }

    [Benchmark]
    public byte[] Sha3_256()
    {
        this.sha3_256.HashInitialize();
        for (var n = 0; n < Repeat; n++)
        {
            this.sha3_256.HashUpdate(this.data, 0, N);
        }

        return this.sha3_256.HashFinal();
    }

    [Benchmark]
    public byte[] Sha3_384()
    {
        this.sha3_384.HashInitialize();
        for (var n = 0; n < Repeat; n++)
        {
            this.sha3_384.HashUpdate(this.data, 0, N);
        }

        return this.sha3_384.HashFinal();
    }

    [Benchmark]
    public byte[] Sha3_512()
    {
        this.sha3_512.HashInitialize();
        for (var n = 0; n < Repeat; n++)
        {
            this.sha3_512.HashUpdate(this.data, 0, N);
        }

        return this.sha3_512.HashFinal();
    }
}
