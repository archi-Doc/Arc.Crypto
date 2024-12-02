// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using Arc.Collections;

namespace Arc.Crypto;

/// <summary>
/// <see cref="RandomVault2"/> is is a random number pool.<br/>
/// It's thread-safe and faster than lock in most cases.<br/>
/// Target: Random integers requested by multiple threads simultaneously<br/><br/>
/// <see cref="RandomVault2"/> generates random integers using random generator<br/>
/// specified by constructor parameters, and takes out integers from the buffer as needed.<br/>
/// </summary>
public class RandomVault2 : RandomUInt64
{
    public const int DefaultBufferSize = 4096;
    private const int SkipVaultThreshold = 256;
    private const int StackSize = 1024;

    static RandomVault2()
    {
        var xo = new Xoshiro256StarStar();
        Pseudo = new RandomVault2(() => xo.NextUInt64(), x => xo.NextBytes(x));
        Crypto = new RandomVault2(null, x => CryptoRandom.NextBytes(x));
    }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool.
    /// </summary>
    public static RandomVault2 Crypto { get; }

    /// <summary>
    ///  Gets the pseudo random number pool.
    /// </summary>
    public static RandomVault2 Pseudo { get; }

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
            // new Span<byte>((byte*)u, remaining).CopyTo(dest);
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
    ///  Initializes a new instance of the <see cref="RandomVault2"/> class.<br/>
    ///  Either <paramref name="nextUInt64"/> or <paramref name="nextBytes"/> must be a valid value.
    /// </summary>
    /// <param name="nextUInt64">Delegate that returns a 64-bit unsigned random integer.</param>
    /// <param name="nextBytes">Delegate that fills the elements of a specified span of bytes with random numbers.</param>
    public RandomVault2(NextUInt64Delegate? nextUInt64, NextBytesDelegate? nextBytes)
    {
        if (nextBytes is not null)
        {
            this.nextBytesFunc = nextBytes;
            this.nextUInt64Func = () => NextBytesToUInt64(this.nextBytesFunc);
        }
        else if (nextUInt64 is not null)
        {
            this.nextBytesFunc = (x) => UInt64ToNextBytes(this.nextUInt64Func!, x);
            this.nextUInt64Func = nextUInt64;
        }
        else
        {
            throw new ArgumentNullException("Valid nextUInt64 or nextBytes is required.");
        }

        var capacity = DefaultBufferSize / sizeof(ulong);
        this.queue = new CircularQueue<ulong>(capacity);
    }

    /// <inheritdoc/>
    public override ulong NextUInt64()
    {
        if (this.queue.TryDequeue(out var value))
        {
            return value;
        }

        // Fill
        ulong provisionedValue = 0;
        Span<byte> byteBuffer = stackalloc byte[StackSize];
        int remaining = this.BufferSize;
        while (remaining > 0)
        {
            var size = Math.Min(StackSize, remaining);

            var span = byteBuffer.Slice(0, size);
            this.nextBytesFunc(span);

            var ulongBuffer = MemoryMarshal.Cast<byte, ulong>(span);
            provisionedValue = ulongBuffer[0];

            for (var i = 1; i < ulongBuffer.Length; i++)
            {
                if (!this.queue.TryEnqueue(ulongBuffer[i]))
                {// Queue is full
                    goto QueueIsFull;
                }
            }

            remaining -= size;
        }

QueueIsFull:
        return provisionedValue;
    }

    public int BufferSize => this.queue.Capacity;

    private readonly NextUInt64Delegate nextUInt64Func;
    private readonly NextBytesDelegate nextBytesFunc;
    private readonly CircularQueue<ulong> queue;
}
