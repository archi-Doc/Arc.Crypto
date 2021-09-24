// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable SA1401 // Fields should be private

namespace Benchmark.Design;

internal class RandomPoolConcurrentQueue
{// A bit slow
    public RandomPoolConcurrentQueue(Func<ulong> nextULong, Action<byte[]> nextBytes, int poolSize = 100)
    {
        this.PoolSize = poolSize;
        this.nextULongDelegate = nextULong;
        this.nextBytesDelegate = nextBytes;

        this.count = this.PoolSize >> 1;
        this.GenerateULong(this.PoolSize);
    }

    public ulong NextULong()
    {
        var c = Interlocked.Increment(ref this.count);
        if (c == this.PoolSize)
        {
            Volatile.Write(ref this.count, 0);
            if (this.queue.Count <= (this.PoolSize >> 1))
            {
                this.GenerateULong(this.PoolSize);
            }
        }

        if (this.queue.TryDequeue(out var u))
        {
            return u;
        }

        lock (this.syncObject)
        {
            return this.nextULongDelegate();
        }
    }

    public Task Generate(int size)
    {
        return this.GenerateULong(size);
    }

    public void Clear()
    {
        this.queue.Clear();
    }

    public int PoolSize { get; }

    private Task GenerateULong(int size)
    {
        return Task.Run(() =>
        {
            lock (this.syncObject)
            {
                for (var i = 0; i < size; i++)
                {
                    this.queue.Enqueue(this.nextULongDelegate());
                }
            }
        });
    }

    private Func<ulong> nextULongDelegate;
    private Action<byte[]> nextBytesDelegate;
    private ConcurrentQueue<ulong> queue = new();
    private object syncObject = new();
    private int count;
}
