// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable SA1401 // Fields should be private

namespace Benchmark.Design;

internal class RandomPoolSplit
{
    private const ulong Empty = 1 << 33;
    public RandomPoolSplit(Func<ulong> nextULong, uint length = 100)
    {
        this.Length = BitOperations.RoundUpToPowerOf2(length);
        this.positionMask = this.Length - 1;
        this.nextULongFunc = nextULong;

        this.array = new ulong[this.Length];
        for (var i = 0; i < this.Length; i++)
        {
            this.array[i] = this.nextULongFunc();
        }

        this.position = 0;
    }

    public ulong NextULong()
    {
        var x = Interlocked.Exchange(ref this.array[this.position & this.positionMask], Empty);
        this.position++;
        if (x == Empty)
        {
            x = Interlocked.Exchange(ref this.array[this.position & this.positionMask], Empty);
            this.position++;
            if (x == Empty)
            {
                goto LockAndGet;
            }
        }

        var y = Interlocked.Exchange(ref this.array[this.position & this.positionMask], Empty);
        this.position++;
        if (y == Empty)
        {
            y = Interlocked.Exchange(ref this.array[this.position & this.positionMask], Empty);
            this.position++;
            if (y == Empty)
            {
                goto LockAndGet;
            }
        }

        return x | (y << 32);

LockAndGet:
        y = x;
        return x | (y << 32);

        lock (this.syncObject)
        {
            return this.nextULongFunc();
        }
    }

    public Task Generate()
    {
        return this.GenerateULong();
    }

    private Task GenerateULong()
    {
        return Task.Run(() =>
        {
            lock (this.syncObject)
            {
            }
        });
    }

    public uint Length { get; }

    private Func<ulong> nextULongFunc;
    private object syncObject = new();

    private uint positionMask;
    private uint position;
    private ulong[] array;
}
