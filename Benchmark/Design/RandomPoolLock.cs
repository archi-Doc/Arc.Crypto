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

internal class RandomPoolLock
{// Bad design
    internal class Pool
    {
        public Pool(uint length)
        {
            this.Array = new ulong[length];
            this.Position = -1;
        }

        internal ulong[] Array;
        internal int Position;
    }

    public RandomPoolLock(Func<ulong> nextULong, uint length = 100)
    {
        this.Length = BitOperations.RoundUpToPowerOf2(length);
        this.nextULongFunc = nextULong;

        this.current = new(this.Length);
        this.Generate(this.current);

        this.shadow = new(this.Length);
        this.Generate(this.shadow);
    }

    public ulong NextULong()
    {
Loop:
        lock (this.current)
        {
            if (this.current.Position >= this.Length)
            {
                lock (this.shadow)
                {
                    (this.current, this.shadow) = (this.shadow, this.current);

                    this.shadow.Position = -1;
                    this.Generate(this.shadow);
                    goto SpinWait;
                }
            }
            else if (this.current.Position < 0)
            {
                goto SpinWait;
            }

            return this.current.Array[this.current.Position++];

SpinWait:
            default(SpinWait).SpinOnce();
            goto Loop;
        }
    }

    public uint Length { get; }

    private void Generate(Pool pool)
    {
        Task.Run(() =>
        {
            lock (pool)
            {
                if (pool.Position >= 0)
                {
                    return;
                }

                for (var i = 0; i < pool.Array.Length; i++)
                {
                    pool.Array[i] = this.nextULongFunc();
                }

                pool.Position = 0;
            }
        });
    }

    private Func<ulong> nextULongFunc;
    private Pool current;
    private Pool shadow;
}
