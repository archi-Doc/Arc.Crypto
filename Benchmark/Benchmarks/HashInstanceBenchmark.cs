// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
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

    public class ObjectPool2<T>
    {
        private readonly ConcurrentQueue<T> objects;
        private readonly Func<T> objectGenerator;

        public ObjectPool2(Func<T> objectGenerator)
        {
            this.objectGenerator = objectGenerator ?? throw new ArgumentNullException(nameof(objectGenerator));
            this.objects = new ConcurrentQueue<T>();
        }

        public T Get() => this.objects.TryDequeue(out T? item) ? item : this.objectGenerator();

        public void Return(T item)
        {
            if (this.objects.Count < 10)
            {
                this.objects.Enqueue(item);
            }
        }
    }

    public HashInstanceBenchmark()
    {
    }

    [Params(10)]
    public int Length { get; set; }

    public byte[] ByteArray { get; set; } = default!;

    public SHA3_256 SHA3Instance { get; } = new();

#pragma warning disable SA1401 // Fields should be private
    public SHA3_256? SHA3Instance2;
#pragma warning restore SA1401 // Fields should be private

    public Obsolete.SHA3_256 SHA3ObsoleteInstance { get; } = new();

    public ObjectPool<SHA3_256> Pool { get; } = new(() => new SHA3_256());

    public ObjectPool2<SHA3_256> Pool2 { get; } = new(() => new SHA3_256());

    public LooseObjectPool<SHA3_256> Pool3 { get; } = new(() => new SHA3_256());

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
    public SHA3_256 Class_Copy()
    {
        this.SHA3Instance2 = this.SHA3Instance;
        return this.SHA3Instance2;
    }

    [Benchmark]
    public SHA3_256 Class_Interlocked()
    {
        Interlocked.Exchange(ref this.SHA3Instance2, this.SHA3Instance);
        return this.SHA3Instance2;
    }

    [Benchmark]
    public SHA3_256 Class_Volatile()
    {
        Volatile.Write(ref this.SHA3Instance2, this.SHA3Instance);
        return this.SHA3Instance2;
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

    [Benchmark]
    public byte[] SHA3Pool2()
    {
        var h = this.Pool2.Get();
        try
        {
            return h.GetHash(this.ByteArray);
        }
        finally
        {
            this.Pool2.Return(h);
        }
    }

    [Benchmark]
    public byte[] SHA3Pool3()
    {
        var h = this.Pool3.Rent();
        try
        {
            return h.GetHash(this.ByteArray);
        }
        finally
        {
            this.Pool3.Return(h);
        }
    }

    [Benchmark]
    public byte[] SHA3Pool3Obsolete()
    {
        var h = this.Pool3.Rent();
        try
        {
            return h.GetHash(this.ByteArray);
        }
        finally
        {
            this.Pool3.ReturnObsolete(h);
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

    /*[Benchmark]
    public (ulong h0, ulong h1, ulong h2, ulong h3) SHA3ULong_NoInstance()
    {
        return this.SHA3Instance.GetHashULong(this.ByteArray);
    }

    [Benchmark]
    public byte[] SHA3_Obsolete_NoInstance()
    {
        return this.SHA3ObsoleteInstance.GetHash(this.ByteArray);
    }*/
}
