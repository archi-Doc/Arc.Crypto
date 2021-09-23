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

internal class RandomPoolSliding
{
    public RandomPoolSliding(Func<ulong> nextULong, uint length = 100)
    {
        this.Length = BitOperations.RoundUpToPowerOf2(length);
        this.positionMask = this.Length - 1;
        this.poolMask = this.Length;
        this.poolBits = BitOperations.TrailingZeroCount(this.poolMask);
        this.nextULongFunc = nextULong;

        this.array = new ulong[this.Length];
        for (var i = 0; i < this.Length; i++)
        {
            this.array[i] = this.nextULongFunc();
        }

        this.position = ulong.MaxValue;
        this.lowerBound = 0;
        this.upperBound = this.Length << 1;
    }

    public ulong NextULong()
    {
        var newPosition = Interlocked.Increment(ref this.position);
        var value = this.array[newPosition & this.positionMask];
        if (this.lowerBound <= newPosition && newPosition < this.upperBound)
        {
            return value;
        }

        /*lock (this.array)
        {
            if (this.lowerBound <= this.position && this.position < this.upperBound)
            {
                return this.array[this.position++ & this.positionMask];
            }
        }*/

        return 0;
    }

    public uint Length { get; }

    private void Generate()
    {
    }

    private Func<ulong> nextULongFunc;
    private ulong positionMask;
    private ulong poolMask;
    private int poolBits;

    private ulong position;
    private ulong lowerBound;
    private ulong upperBound;
    private ulong[] array;
}
