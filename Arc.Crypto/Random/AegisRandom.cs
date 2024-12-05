// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto.Random;

/// <summary>
/// A high-performance cryptographically secure pseudo-random number generator combining RandomNumberGenerator and AEGIS-256.<br/>
/// Please note that this is not thread-safe.
/// </summary>
public class AegisRandom
{
    private const int RandomSize = 1024;
    private const int KeyNonceSize = Aegis256.KeySize + Aegis256.NonceSize;
    private const int SourceSize = RandomSize + KeyNonceSize;
    private const int DestinationSize = RandomSize + KeyNonceSize + Aegis256.MinTagSize;
    private const int StoreSize = 4096;

    #region FieldAndProperty

    private readonly Xoshiro256StarStar xo = new();
    private readonly byte[] source = new byte[SourceSize];
    private readonly byte[] destination = new byte[DestinationSize];
    private readonly byte[] store = new byte[StoreSize];
    private int position;
    private int storeRemaining;

    private int remaining => RandomSize - this.position;

    #endregion

    public AegisRandom()
    {
        this.FillBuffer();
    }

    public void NextBytes(Span<byte> destination)
    {
        while (destination.Length > 0)
        {
            if (this.remaining == 0)
            {
                this.FillBuffer();
            }

            var size = Math.Min(destination.Length, this.remaining);
            this.destination.AsSpan(this.position, size).CopyTo(destination);
            destination = destination.Slice(size);
            this.position += size;
        }
    }

    private void FillBuffer()
    {
        Span<byte> keyNonce = stackalloc byte[KeyNonceSize];
        this.destination.AsSpan(RandomSize, KeyNonceSize).CopyTo(keyNonce);

        if (this.storeRemaining < KeyNonceSize)
        {
            RandomNumberGenerator.Fill(this.store);
            this.storeRemaining = StoreSize;
        }

        Span<byte> keyNonce2 = stackalloc byte[KeyNonceSize];
        this.store.AsSpan(StoreSize - this.storeRemaining, KeyNonceSize).CopyTo(keyNonce2);
        this.storeRemaining -= KeyNonceSize;

        var s = MemoryMarshal.Cast<byte, ulong>(keyNonce);
        var s2 = MemoryMarshal.Cast<byte, ulong>(keyNonce2);
        for (var i = 0; i < s.Length; i++)
        {
            s[i] ^= s2[i];
        }

        s[0] ^= (ulong)Stopwatch.GetTimestamp();

        this.xo.NextBytes(this.source);
        Aegis256.Encrypt(this.destination, this.source, keyNonce.Slice(Aegis256.KeySize, Aegis256.NonceSize), keyNonce.Slice(0, Aegis256.KeySize));
        this.position = 0;
    }
}
