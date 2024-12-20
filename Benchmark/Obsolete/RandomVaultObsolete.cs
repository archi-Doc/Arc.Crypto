﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Collections;
using Arc.Crypto.Random;

namespace Arc.Crypto;

/// <summary>
/// <see cref="RandomVaultObsolete"/> is is a random number pool.<br/>
/// It's thread-safe and faster than lock() in most cases.<br/>
/// Target: Random integers requested by multiple threads simultaneously<br/><br/>
/// <see cref="RandomVaultObsolete"/> generates random integers using random generator<br/>
/// specified by constructor parameters, and takes out integers from the buffer as needed.
/// </summary>
public class RandomVaultObsolete : RandomUInt64
{
    public const int DefaultBufferSize = 4096;

    private const int SkipVaultThreshold = 64; // If the size of the random bytes exceeds this value, they will be generated directly without using the RandomVaultObsolete.
    private const int StackSize = 1024; // Specifies the stack size to be used when generating random numbers.

    static RandomVaultObsolete()
    {
        var xo = new Xoshiro256StarStar();
        Xoshiro = new RandomVaultObsolete(x => xo.NextBytes(x), false);
        RandomNumberGenerator = new RandomVaultObsolete(x => System.Security.Cryptography.RandomNumberGenerator.Fill(x), true);
        Libsodium = new RandomVaultObsolete(x => CryptoRandom.NextBytes(x), true);
        var aegis = new AegisRandom();
        Aegis = new RandomVaultObsolete(x => aegis.NextBytes(x), false);
    }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool (<see cref="AegisRandom"/>).
    /// </summary>
    public static RandomVaultObsolete Aegis { get; }

    /// <summary>
    ///  Gets the pseudo random number pool (<see cref="Xoshiro256StarStar"/>).
    /// </summary>
    public static RandomVaultObsolete Xoshiro { get; }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool (<see cref="RandomNumberGenerator.Fill(Span{byte})"/>).
    /// </summary>
    public static RandomVaultObsolete RandomNumberGenerator { get; }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool (Libsodium: <see cref="CryptoRandom.NextBytes(Span{byte})"/>).
    /// </summary>
    public static RandomVaultObsolete Libsodium { get; }

    /// <summary>
    ///  Initializes a new instance of the <see cref="RandomVaultObsolete"/> class.<br/>
    /// </summary>
    /// <param name="nextBytes">Delegate that fills the elements of a specified span of bytes with random numbers.</param>
    /// <param name="threadSafe">Indicates whether nextBytes action is thread-safe.</param>
    public RandomVaultObsolete(Action<Span<byte>> nextBytes, bool threadSafe)
    {
        this.nextBytesFunc = nextBytes;
        this.threadSafe = threadSafe;

        this.BufferSize = DefaultBufferSize;
        this.queue = new CircularQueue<ulong>(this.BufferSize / sizeof(ulong));
    }

    /// <inheritdoc/>
    public override ulong NextUInt64()
    {
        if (this.queue.TryDequeue(out var value))
        {
            return value;
        }

        // Since the queue is empty, add random numbers equal to half the size of the buffer.
        if (this.threadSafe)
        {
            return PrepareQueue();
        }
        else
        {
            lock (this.SyncObject)
            {
                return PrepareQueue();
            }
        }

        ulong PrepareQueue()
        {
            bool provisioned = false;
            ulong provisionedValue = 0;
            Span<byte> byteBuffer = stackalloc byte[StackSize];
            int remaining = this.BufferSize >> 1;
            while (remaining > 0)
            {
                var size = Math.Min(StackSize, remaining);

                var span = byteBuffer.Slice(0, size);
                this.nextBytesFunc(span);

                var ulongBuffer = MemoryMarshal.Cast<byte, ulong>(span);
                int i;
                if (provisioned)
                {
                    i = 0;
                }
                else
                {
                    provisioned = true;
                    provisionedValue = ulongBuffer[0];
                    i = 1;
                }

                for (; i < ulongBuffer.Length; i++)
                {
                    if (!this.queue.TryEnqueue(ulongBuffer[i]))
                    {// The queue is full
                        return provisionedValue;
                    }
                }

                remaining -= size;
            }

            return provisionedValue;
        }
    }

    public override void NextBytes(Span<byte> buffer)
    {
        if (buffer.Length < SkipVaultThreshold)
        {
            base.NextBytes(buffer);
        }
        else
        {// If the size is large, the performance of RandomVaultObsolete decreases, so the original function is called instead.
            if (this.threadSafe)
            {
                this.nextBytesFunc(buffer);
            }
            else
            {
                lock (this.SyncObject)
                {
                    this.nextBytesFunc(buffer);
                }
            }
        }
    }

    public int BufferSize { get; }

    private readonly Action<Span<byte>> nextBytesFunc;
    private readonly bool threadSafe;
    private readonly CircularQueue<ulong> queue;

    private object SyncObject => this.queue;
}
