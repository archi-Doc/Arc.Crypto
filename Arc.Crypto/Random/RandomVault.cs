// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Arc.Crypto.Random;

namespace Arc.Crypto;

/// <summary>
/// <see cref="RandomVault"/> is is a thread-safe random number pool.<br/>
/// Target: Random integers requested by multiple threads simultaneously<br/><br/>
/// <see cref="RandomVault"/> generates random integers using random generator<br/>
/// specified by constructor parameters, and takes out integers from the buffer as needed.
/// </summary>
public class RandomVault : RandomUInt64
{
    private const int DefaultBufferSize = 4096;
    private const int DefaultSkipVaultThreshold = 256;

    static RandomVault()
    {
        var xo = new Xoshiro256StarStar();
        Xoshiro = new RandomVault(x => xo.NextBytes(x), 16);
        RandomNumberGenerator = new RandomVault(x => System.Security.Cryptography.RandomNumberGenerator.Fill(x));
        Libsodium = new RandomVault(x => CryptoRandom.NextBytes(x));
        var aegis = new AegisRandom();
        Aegis = new RandomVault(x => aegis.NextBytes(x), 16);
    }

    /// <summary>
    /// Gets the default cryptographically secure pseudo random number pool (<see cref="AegisRandom"/>).
    /// </summary>
    public static RandomVault Default => Aegis;

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool (<see cref="AegisRandom"/>).
    /// </summary>
    public static RandomVault Aegis { get; }

    /// <summary>
    ///  Gets the pseudo random number pool (<see cref="Xoshiro256StarStar"/>).
    /// </summary>
    public static RandomVault Xoshiro { get; }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool (<see cref="RandomNumberGenerator.Fill(Span{byte})"/>).
    /// </summary>
    public static RandomVault RandomNumberGenerator { get; }

    /// <summary>
    ///  Gets the cryptographically secure pseudo random number pool (Libsodium: <see cref="CryptoRandom.NextBytes(Span{byte})"/>).
    /// </summary>
    public static RandomVault Libsodium { get; }

    /// <summary>
    ///  Initializes a new instance of the <see cref="RandomVault"/> class.<br/>
    /// </summary>
    /// <param name="nextBytes">Delegate that fills the elements of a specified span of bytes with random numbers.</param>
    /// <param name="skipVaultThreshold">Threshold for skipping the vault and generating random bytes directly.</param>
    public RandomVault(Action<Span<byte>> nextBytes, int skipVaultThreshold = DefaultSkipVaultThreshold)
    {
        this.nextBytesFunc = nextBytes;
        this.BufferSize = DefaultBufferSize;
        this.buffer = new byte[this.BufferSize];
        this.skipVaultThreshold = Math.Min(skipVaultThreshold, this.BufferSize);
    }

    /// <summary>
    /// Generates the next random 64-bit unsigned integer.
    /// </summary>
    /// <returns>A random 64-bit unsigned integer.</returns>
    public override ulong NextUInt64()
    {
        using (this.lockObject.EnterScope())
        {
            if (this.remaining >= sizeof(ulong))
            {
                var value = MemoryMarshal.Read<ulong>(this.buffer.AsSpan(this.position));
                this.remaining -= sizeof(ulong);
                return value;
            }
            else
            {
                Span<byte> tmp = stackalloc byte[sizeof(ulong)];
                var a = this.remaining;
                var b = sizeof(ulong) - this.remaining;
                this.buffer.AsSpan(this.position, a).CopyTo(tmp);

                this.PrepareBuffer();
                this.buffer.AsSpan(this.position, b).CopyTo(tmp.Slice(a));
                this.remaining -= b;

                return MemoryMarshal.Read<ulong>(tmp);
            }
        }
    }

    /// <summary>
    /// Fills the elements of a specified span of bytes with random numbers.
    /// </summary>
    /// <param name="destination">The span to fill with random numbers.</param>
    public override void NextBytes(Span<byte> destination)
    {
        using (this.lockObject.EnterScope())
        {
            // First, attempt to consume the prepared buffer.
            var n = Math.Min(destination.Length, this.remaining);
            if (n > 0)
            {
                this.buffer.AsSpan(this.position, n).CopyTo(destination);
                this.remaining -= n;
                destination = destination.Slice(n);
            }

            if (destination.Length == 0)
            {
                return;
            }

            if (destination.Length > this.skipVaultThreshold)
            {// If it is above the threshold, use the underlying function.
                this.nextBytesFunc(destination);
                // this.PrepareBuffer();
            }
            else
            {// For other cases, prepare the buffer first and then copy (it is ensured that destination.Length is less than or equal to skipVaultThreshold/BufferSize).
                this.PrepareBuffer();
                this.buffer.AsSpan(0, destination.Length).CopyTo(destination);
                this.remaining -= destination.Length;
            }
        }
    }

    /// <summary>
    /// Prepares the buffer by filling it with random bytes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void PrepareBuffer()
    {
        this.nextBytesFunc(this.buffer);
        this.remaining = this.BufferSize;
    }

    /// <summary>
    /// Gets the size of the buffer.
    /// </summary>
    public int BufferSize { get; }

    private readonly Action<Span<byte>> nextBytesFunc;
    private readonly int skipVaultThreshold;
    private readonly Lock lockObject = new();
    private readonly byte[] buffer;
    private int remaining;

    private int position => this.BufferSize - this.remaining;
}
