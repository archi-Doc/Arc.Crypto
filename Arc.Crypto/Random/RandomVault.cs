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

#pragma warning disable SA1124 // Do not use regions
#pragma warning disable SA1401 // Fields should be private

namespace Arc.Crypto;

public class RandomVault : RandomULong
{
    public const uint MinimumVaultSize = 32;

    public delegate void NextBytesDelegate(Span<byte> data);

    private static unsafe ulong NextBytesToULong(NextBytesDelegate nextBytes)
    {
        ulong u;
        Span<byte> b = stackalloc byte[8];
        nextBytes(b);
        fixed (byte* bp = b)
        {
            u = *(ulong*)bp;
        }

        return u;
    }

    public RandomVault(Func<ulong>? nextULong, NextBytesDelegate nextBytes, uint vaultSize = 100)
    {
        this.VaultSize = BitOperations.RoundUpToPowerOf2(vaultSize);
        if (this.VaultSize < MinimumVaultSize)
        {
            this.VaultSize = MinimumVaultSize;
        }

        this.halfSize = this.VaultSize >> 1;
        this.positionMask = this.VaultSize - 1;
        this.halfMask = this.positionMask >> 1;
        this.nextBytes = nextBytes;
        if (nextULong != null)
        {
            this.nextULongFunc = nextULong;
        }
        else
        {
            // this.nextULongFunc = () => NextBytesToULong(this.nextBytes);
            this.nextULongFunc = () =>
            {// Same as above.
                Span<byte> b = stackalloc byte[8];
                this.nextBytes(b);
                return BitConverter.ToUInt64(b);
            };
        }

        this.array = new ulong[this.VaultSize];
        this.FillArray(1, this.VaultSize); // array[0] is not used.
        this.position = 0;
        this.lowerBound = 0;
        this.upperBound = this.VaultSize;
    }

    /// <summary>
    /// [0, long.MaxValue]<br/>
    /// Returns a random integer.
    /// </summary>
    /// <returns>A 64-bit signed integer [0, long.MaxValue].</returns>
    public override ulong NextULong()
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

    public uint VaultSize { get; }

    private Task GenerateInternal()
    {
        return Task.Run(() =>
        {
            while (true)
            {
                lock (this.syncObject)
                {
                    // Fixed:  this.lowerBound, this.upperBound
                    // Not fixed: this.position
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
                            Volatile.Write(ref this.upperBound, this.lowerBound + this.VaultSize);
                        }
                    }
                    else
                    {
                        if ((this.upperBound - this.lowerBound) <= this.halfSize)
                        {// Extend the upper bound.
                            var index = (uint)(this.upperBound & this.positionMask);
                            this.FillArray(index, index + this.halfSize);
                            Volatile.Write(ref this.upperBound, this.lowerBound + this.VaultSize);
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
