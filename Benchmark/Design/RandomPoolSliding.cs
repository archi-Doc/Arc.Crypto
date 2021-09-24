// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#pragma warning disable SA1401 // Fields should be private

namespace Benchmark.Design;

internal class RandomPoolSliding
{
    public const uint MinimumPoolSize = 32;

    public delegate void NextBytesDelegate(Span<byte> data);

    public RandomPoolSliding(Func<ulong> nextULong, NextBytesDelegate nextBytes, uint poolSize = 100)
    {
        this.PoolSize = BitOperations.RoundUpToPowerOf2(poolSize);
        if (this.PoolSize < MinimumPoolSize)
        {
            this.PoolSize = MinimumPoolSize;
        }

        this.halfSize = this.PoolSize >> 1;
        this.positionMask = this.PoolSize - 1;
        this.halfMask = this.positionMask >> 1;
        // this.poolMask = this.Length;
        // this.poolBits = BitOperations.TrailingZeroCount(this.poolMask);
        this.nextULongFunc = nextULong;
        this.nextBytes = nextBytes;

        this.array = new ulong[this.PoolSize];
        this.FillArray(1, this.PoolSize); // array[0] is not used.
        this.position = 0;
        this.lowerBound = 0;
        this.upperBound = this.PoolSize;
    }

    public ulong NextULong()
    {
        var upper = Volatile.Read(ref this.upperBound);
        if (this.position > upper)
        {
            goto LockAndGet;
        }

        var lower = Volatile.Read(ref this.lowerBound);
        var newPosition = Interlocked.Increment(ref this.position);
        var value = this.array[newPosition & this.positionMask];

        if (lower == Volatile.Read(ref this.lowerBound) && upper == Volatile.Read(ref this.upperBound))
        {// lower/upper bounds are not changed.
            if (lower <= newPosition && newPosition < upper)
            {// value is valid.
                if ((newPosition & this.halfMask) == 0)
                {
                    this.GenerateInternal();
                }

                return value;
            }
        }
        else
        {// lower/upper bounds are changed.
        }

LockAndGet:
        lock (this.syncObject)
        {
            return this.nextULongFunc();
        }
    }

    public Task Generate() => this.GenerateInternal();

    public uint PoolSize { get; }

    private Task GenerateInternal()
    {
        return Task.Run(() =>
        {
            while (true)
            {
                lock (this.syncObject)
                {
                    // Fixed:  this.lowerBound, this.upperBound
                    // Subject to change: this.position
                    var position = Volatile.Read(ref this.position);

                    if (position < this.lowerBound)
                    {
                        return;
                    }
                    else if (position < (this.lowerBound + this.halfSize))
                    {
                        if ((this.upperBound - this.lowerBound) > this.halfSize)
                        {// Enough
                            return;
                        }
                        else
                        {// Extend the upper bound.
                            var index = (uint)(this.upperBound & this.positionMask);
                            this.FillArray(index, index + this.halfSize);
                            Volatile.Write(ref this.upperBound, this.lowerBound + this.PoolSize);
                        }
                    }
                    else
                    {
                        if ((this.upperBound - this.lowerBound) <= this.halfSize)
                        {// Extend the upper bound.
                            var index = (uint)(this.upperBound & this.positionMask);
                            this.FillArray(index, index + this.halfSize);
                            Volatile.Write(ref this.upperBound, this.lowerBound + this.PoolSize);
                        }
                        else
                        {// Raise the lower bound.
                            Volatile.Write(ref this.lowerBound, this.lowerBound + this.halfSize);
                        }
                    }
                }
            }
        });
    }

    private void FillArray(uint start, uint end)
    {
        var span = MemoryMarshal.AsBytes(this.array.AsSpan((int)start, (int)(end - start)));
        this.nextBytes(span);
    }

    private Func<ulong> nextULongFunc;
    private NextBytesDelegate nextBytes;
    private object syncObject = new();
    private ulong positionMask;
    private ulong halfMask;
    private uint halfSize;

    private ulong position;
    private ulong lowerBound;
    private ulong upperBound;
    private ulong[] array;
}
