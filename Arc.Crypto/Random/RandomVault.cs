// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Arc.Crypto;

/// <summary>
/// <see cref="RandomVault"/> is is a random number pool.<br/>
/// It's thread-safe and faster than lock in most cases.<br/>
/// Target: Random integers requested by multiple threads simultaneously<br/><br/>
/// <see cref="RandomVault"/> generates random integers using random generator<br/>
/// specified by constructor parameters, and takes out integers from the buffer as needed.<br/>
/// </summary>
public class RandomVault : RandomUInt64
{
    public const uint MinimumVaultSize = 32;
    public const uint DefaultVaultSize = 128;

    static RandomVault()
    {
        var xo = new Xoshiro256StarStar();
        Pseudo = new RandomVault(() => xo.NextUInt64(), x => xo.NextBytes(x), 1024);
        // Crypto = new RandomVault(null, x => RandomNumberGenerator.Fill(x), 1024);
        Crypto = new RandomVault(null, x => CryptoRandom.NextBytes(x), 1024);
    }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool.
    /// </summary>
    public static RandomVault Crypto { get; }

    /// <summary>
    ///  Gets the pseudo random number pool.
    /// </summary>
    public static RandomVault Pseudo { get; }

    /// <summary>
    /// Defines the type of delegate that returns a 64-bit unsigned random integer.
    /// </summary>
    /// <returns>A 64-bit unsigned integer [0, 2^64-1].</returns>
    public delegate ulong NextUInt64Delegate();

    /// <summary>
    /// Defines the type of delegate that fills the elements of a specified span of bytes with random numbers.
    /// </summary>
    /// <param name="data">The array to be filled with random numbers.</param>
    public delegate void NextBytesDelegate(Span<byte> data);

    private static unsafe ulong NextBytesToUInt64(NextBytesDelegate nextBytes)
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

    private static unsafe void UInt64ToNextBytes(NextUInt64Delegate nextUInt64Func, Span<byte> buffer)
    {
        var remaining = buffer.Length;
        fixed (byte* pb = buffer)
        {
            byte* dest = pb;
            while (remaining >= sizeof(ulong))
            {
                *(ulong*)dest = nextUInt64Func();
                dest += sizeof(ulong);
                remaining -= sizeof(ulong);
            }

            if (remaining == 0)
            {
                return;
            }

            // 0 < remaining < 8
            var u = nextUInt64Func();
            if (remaining >= sizeof(uint))
            {
                *(uint*)dest = (uint)u;
                dest += sizeof(uint);
                remaining -= sizeof(uint);
                u >>= 32;
            }

            // 0 < remaining < 4
            byte* pu = (byte*)&u;
            while (remaining-- > 0)
            {
                *dest++ = *pu++;
            }
        }
    }

    /// <summary>
    ///  Initializes a new instance of the <see cref="RandomVault"/> class.<br/>
    ///  Either <paramref name="nextUInt64"/> or <paramref name="nextBytes"/> must be a valid value.
    /// </summary>
    /// <param name="nextUInt64">Delegate that returns a 64-bit unsigned random integer.</param>
    /// <param name="nextBytes">Delegate that fills the elements of a specified span of bytes with random numbers.</param>
    /// <param name="vaultSize">The number of 64-bit integers stored in <see cref="RandomVault"/>.</param>
    public RandomVault(NextUInt64Delegate? nextUInt64, NextBytesDelegate? nextBytes, uint vaultSize = DefaultVaultSize)
    {
        if (nextUInt64 == null && nextBytes == null)
        {
            throw new ArgumentNullException("Valid nextUInt64 or nextBytes is required.");
        }

        this.VaultSize = BitOperations.RoundUpToPowerOf2(vaultSize);
        if (this.VaultSize < MinimumVaultSize)
        {
            this.VaultSize = MinimumVaultSize;
        }

        this.halfSize = this.VaultSize >> 1;
        this.positionMask = this.VaultSize - 1;
        this.halfMask = this.positionMask >> 1;
        if (nextBytes != null)
        {
            this.nextBytesFunc = nextBytes;
        }
        else
        {// nextUInt64 is not null.
            this.nextBytesFunc = (x) => UInt64ToNextBytes(this.nextUInt64Func!, x);
        }

        if (nextUInt64 != null)
        {
            this.nextUInt64Func = nextUInt64;
        }
        else
        {// nextBytes is not null.
            this.nextUInt64Func = () => NextBytesToUInt64(this.nextBytesFunc);
            /*this.nextUInt64Func = () =>
            {// Same as above.
                Span<byte> b = stackalloc byte[8];
                this.nextBytesFunc(b);
                return BitConverter.ToUInt64(b);
            };*/
        }

        this.array = new ulong[this.VaultSize];
        this.FillArray(1, this.VaultSize); // array[0] is not used.
        this.position = 0;
        this.lowerBound = 0;
        this.upperBound = this.VaultSize;
    }

    /// <inheritdoc/>
    public override ulong NextUInt64()
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
        using (this.lockObject.EnterScope())
        {
            return this.nextUInt64Func();
        }
    }

    public Task GenerateRandomForTest() => this.GenerateInternal();

    /// <summary>
    /// Gets the number of 64-bit integers stored in <see cref="RandomVault"/>.
    /// </summary>
    public uint VaultSize { get; }

    private Task GenerateInternal()
    {
        if (this.isTaskRunning)
        {
            return Task.CompletedTask;
        }

        this.isTaskRunning = true;
        return Task.Run(() =>
        {
            try
            {
                while (true)
                {
                    using (this.lockObject.EnterScope())
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
            }
            finally
            {
                this.isTaskRunning = false;
            }
        });
    }

    private void FillArray(uint start, uint end)
    {
        var span = MemoryMarshal.AsBytes(this.array.AsSpan((int)start, (int)(end - start)));
        this.nextBytesFunc(span);
    }

    private NextUInt64Delegate nextUInt64Func;
    private NextBytesDelegate nextBytesFunc;
    private Lock lockObject = new();
    private ulong positionMask;
    private ulong halfMask;
    private uint halfSize;

    private ulong position;
    private ulong lowerBound;
    private ulong upperBound;
    private ulong[] array;
    private bool isTaskRunning = false;
}
