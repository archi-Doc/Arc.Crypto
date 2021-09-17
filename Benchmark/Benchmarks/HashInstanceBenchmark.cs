// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Concurrent;
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
    public class ObjectPool<T>
    {
        private readonly ConcurrentBag<T> objects;
        private readonly Func<T> objectGenerator;

        public ObjectPool(Func<T> objectGenerator)
        {
            this.objectGenerator = objectGenerator ?? throw new ArgumentNullException(nameof(objectGenerator));
            this.objects = new ConcurrentBag<T>();
        }

        public T Get() => this.objects.TryTake(out T? item) ? item : this.objectGenerator();

        public void Return(T item) => this.objects.Add(item);
    }

    public HashInstanceBenchmark()
    {
    }

    [Params(10)]
    public int Length { get; set; }

    public byte[] ByteArray { get; set; } = default!;

    public SHA3_256 SHA3Instance { get; } = new();

    public Obsolete.SHA3_256 SHA3ObsoleteInstance { get; } = new();

    public ObjectPool<SHA3_256> Pool { get; } = new(() => new SHA3_256());

    [GlobalSetup]
    public void Setup()
    {
        this.ByteArray = new byte[this.Length];
        for (var i = 0; i < this.Length; i++)
        {
            this.ByteArray[i] = (byte)i;
        }
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
    public byte[] SHA3Pool()
    {
        var h = this.Pool.Get();
        try
        {
            return h.GetHash(this.ByteArray);
        }
        finally
        {
            this.Pool.Return(h);
        }
    }

    /*[Benchmark]
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
    }*/

    [Benchmark]
    public byte[] SHA3_NoInstance()
    {
        return this.SHA3Instance.GetHash(this.ByteArray);
    }

    [Benchmark]
    public (ulong h0, ulong h1, ulong h2, ulong h3) SHA3ULong_NoInstance()
    {
        return this.SHA3Instance.GetHashULong(this.ByteArray);
    }

    [Benchmark]
    public byte[] SHA3_Obsolete_NoInstance()
    {
        return this.SHA3ObsoleteInstance.GetHash(this.ByteArray);
    }
}
