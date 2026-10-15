// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// A high-performance cryptographically secure pseudo-random number generator that outputs the AEGIS-256 keystream.<br/>
/// Every 1024 output bytes, the key and nonce are replaced with 64 unused keystream bytes mixed with fresh <see cref="RandomNumberGenerator"/> bytes.<br/>
/// Please note that this is not thread-safe; use <see cref="RandomVault.Aegis"/> for concurrent access.
/// </summary>
/// <remarks>
/// When hardware AES (x86 AES-NI or ARMv8 AES) is unavailable or disabled, the portable fallback uses lookup tables and is not constant-time,
/// so it may leak secret state through cache-timing side channels.
/// </remarks>
public class AegisRandom
{
    private const int RandomSize = 1024;
    private const int KeyNonceSize = Aegis256.KeySize + Aegis256.NonceSize;
    private const int SourceSize = RandomSize + KeyNonceSize;
    private const int StoreSize = 4096;

    #region FieldAndProperty

    // private readonly Xoshiro256StarStar xo = new(); // Not needed: the freshly keyed AEGIS-256 keystream alone is the output.
    private readonly byte[] source = new byte[SourceSize]; // Always zero, so encrypting it yields the raw keystream.
    private readonly byte[] destination = new byte[SourceSize];
    private readonly byte[] store = new byte[StoreSize];
    private int position;
    private int storeRemaining;

    private int remaining => RandomSize - this.position;

    #endregion

    /// <summary>
    /// Initializes a new instance of the <see cref="AegisRandom"/> class.
    /// </summary>
    public AegisRandom()
    {
        this.FillBuffer();
    }

    /// <summary>
    /// Fills the elements of a specified span of bytes with random numbers.
    /// </summary>
    /// <param name="destination">The span to fill with random numbers.</param>
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

        // this.xo.NextBytes(this.source); // Not needed: source stays zero and the output is the raw AEGIS-256 keystream.
        // The output is used as a key stream, so the authentication tag is never needed.
        Aegis256.Encrypt(this.destination, this.source, keyNonce.Slice(Aegis256.KeySize, Aegis256.NonceSize), keyNonce.Slice(0, Aegis256.KeySize), default, 0);
        this.position = 0;
    }
}
