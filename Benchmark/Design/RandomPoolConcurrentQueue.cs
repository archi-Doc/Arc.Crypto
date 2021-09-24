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
{// Slow
    public RandomPoolConcurrentQueue(Func<ulong> nextULong, int size = 100)
    {
        this.Size = size;
        this.nextULongFunc = nextULong;

        this.count = this.Size >> 1;
        this.GenerateULong(this.Size);
    }

    public ulong NextULong()
    {
        var c = Interlocked.Increment(ref this.count);
        if (c == this.Size)
        {
            Volatile.Write(ref this.count, 0);
            if (this.queue.Count <= (this.Size >> 1))
            {
                this.GenerateULong(this.Size);
            }
        }

        if (this.queue.TryDequeue(out var u))
        {
            return u;
        }

        lock (this.syncObject)
        {
            return this.nextULongFunc();
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

    public int Size { get; }

    private Task GenerateULong(int size)
    {
        return Task.Run(() =>
        {
            lock (this.syncObject)
            {
                for (var i = 0; i < size; i++)
                {
                    this.queue.Enqueue(this.nextULongFunc());
                }
            }
        });
    }

    private Func<ulong> nextULongFunc;
    private ConcurrentQueue<ulong> queue = new();
    private object syncObject = new();
    private int count;
}
