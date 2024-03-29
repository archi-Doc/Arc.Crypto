﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

#pragma warning disable SA1402 // File may only contain a single type
#pragma warning disable SA1649 // File name should match first type name

namespace Benchmark.Obsolete;

/// <summary>
/// SHA3-256 Hash Class.
/// </summary>
public class Sha3_256 : Sha3
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Sha3_256"/> class.
    /// </summary>
    public Sha3_256()
    {
        this.Sponge = new KeccakSponge(256);
    }

    /// <inheritdoc/>
    public override string HashName => "SHA3-256";

    /// <inheritdoc/>
    public override uint HashBits => 256;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;
}

/// <summary>
/// SHA3-384 Hash Class.
/// </summary>
public class Sha3_384 : Sha3
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Sha3_384"/> class.
    /// </summary>
    public Sha3_384()
    {
        this.Sponge = new KeccakSponge(384);
    }

    /// <inheritdoc/>
    public override string HashName => "SHA3-384";

    /// <inheritdoc/>
    public override uint HashBits => 384;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;
}

/// <summary>
/// SHA3-512 Hash Class.
/// </summary>
public class Sha3_512 : Sha3
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Sha3_512"/> class.
    /// </summary>
    public Sha3_512()
    {
        this.Sponge = new KeccakSponge(512);
    }

    /// <inheritdoc/>
    public override string HashName => "SHA3-512";

    /// <inheritdoc/>
    public override uint HashBits => 512;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;
}

/// <summary>
/// Wrapper class for SHA3.
/// </summary>
public abstract class Sha3 : Arc.Crypto.IHash
{
    /// <inheritdoc/>
    public virtual string HashName => "SHA3 Wrapper";

    /// <inheritdoc/>
    public virtual uint HashBits => 0;

    /// <inheritdoc/>
    public virtual bool IsCryptographic => false;

    /// <summary>
    /// Gets or sets the instance of KeccakSponge.
    /// </summary>
    internal KeccakSponge? Sponge { get; set; }

    /// <inheritdoc/>
    public byte[] GetHash(ReadOnlySpan<byte> input)
    {
        this.HashInitialize();
        this.HashUpdate(input);
        return this.HashFinal();
    }

    /// <inheritdoc/>
    public byte[] GetHash(byte[] input, int inputOffset, int inputCount)
    {
        this.HashInitialize();
        this.HashUpdate(input, inputOffset, inputCount);
        return this.HashFinal();
    }

    /// <inheritdoc/>
    public byte[] HashFinal() => this.Sponge!.Squeeze();

    /// <inheritdoc/>
    public void HashInitialize() => this.Sponge!.Initialize();

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input) => this.Sponge!.Absorb(input);

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount) => this.Sponge!.Absorb(input.AsSpan(inputOffset, inputCount));
}

/// <summary>
/// Represents a managed implementation of the Keccak sponge function and permutation.
/// </summary>
internal unsafe class KeccakSponge
{
    private const int StateLength = 25;

    private static readonly ulong[] RoundConstants = new ulong[]
    {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

    private int statePosition;
    private ulong[] state;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeccakSponge"/> class. Protected constructor to prevent instantiation.
    /// </summary>
    /// <param name="outputBits">The number of hash size in bits.</param>
    public KeccakSponge(int outputBits)
    {
        if (outputBits != 224 && outputBits != 256 && outputBits != 384 && outputBits != 512)
        {
            throw new ArgumentOutOfRangeException();
        }

        this.OutputBits = outputBits;
        this.Bitrate = 1600 - (this.OutputBits * 2);

        this.state = new ulong[StateLength];
        this.statePosition = -1; // force initialize.
        this.Initialize();
    }

    /// <summary>
    /// Gets the number of hash size in bits.
    /// </summary>
    public int OutputBits { get; }

    /// <summary>
    ///  Gets the number of bitrate (1600 - (this.OutputBits * 2)).
    /// </summary>
    public int Bitrate { get; }

    /// <summary>
    /// Initializes the sponge state.
    /// </summary>
    public unsafe void Initialize()
    {
        if (this.statePosition == 0)
        { // already initialized.
            return;
        }

        this.statePosition = 0;

        unsafe
        {
            fixed (void* p = this.state)
            {
                Clear(p, StateLength * sizeof(ulong));
            }
        }
    }

    /// <summary>
    /// Absorbs data into the sponge state.
    /// </summary>
    /// <param name="bytes">The read-only span to absorb.</param>
    public unsafe void Absorb(ReadOnlySpan<byte> bytes)
    {
        unsafe
        {
            var length = bytes.Length;
            fixed (byte* b = bytes)
            {
                fixed (ulong* stateHead = this.state)
            {
                byte* input = b;
                byte* s = (byte*)stateHead + this.statePosition;
                while (length > 0)
                {
                    int to_take = Math.Min(length, (this.Bitrate / 8) - this.statePosition);
                    length -= to_take;

                    while (to_take != 0 & (this.statePosition % 8) != 0)
                    {
                        /*this.state[this.statePosition / 8] ^= (ulong)input[0] << (8 * (this.statePosition % 8));
                        s++;
                        input++;*/
                        *s++ ^= *input++;
                        this.statePosition++;
                        to_take--;
                    }

                    while (to_take != 0 && to_take % 8 == 0)
                    {
                        *(ulong*)s ^= *(ulong*)input;
                        s += 8;
                        input += 8;
                        this.statePosition += 8;
                        to_take -= 8;
                    }

                    while (to_take != 0)
                    {
                        /*this.state[this.statePosition / 8] ^= (ulong)input[0] << (8 * (this.statePosition % 8));
                        s++;
                        input++;*/
                        *s++ ^= *input++;
                        this.statePosition++;
                        to_take--;
                    }

                    if (this.statePosition == (this.Bitrate / 8))
                    {
                        this.Permute(this.state);
                        s = (byte*)stateHead;
                        this.statePosition = 0;
                    }
                }
            }
            }
        }
    }

    /// <summary>
    /// Squeezes the hash out of the sponge state.
    /// </summary>
    /// <returns>A hash of the input data.</returns>
    public unsafe byte[] Squeeze()
    { // state 0..(this.Bitrate / 8) : data, (this.Bitrate / 8)..100
        this.state[this.statePosition / 8] ^= 0x06UL << (8 * (this.statePosition % 8));
        this.state[(this.Bitrate / 64) - 1] ^= 0x80UL << 56;

        this.Permute(this.state);

        // copy result from this.state.
        var resultSize = this.OutputBits / 8;
        var result = new byte[resultSize];
        unsafe
        {
            fixed (void* source = this.state, destination = result)
            {
                Buffer.MemoryCopy(source, destination, resultSize, resultSize);
            }
        }

        this.statePosition = -1; // force initialize.
        this.Initialize();

        return result;
    }

    /// <summary>
    /// Fills target with zeros.
    /// </summary>
    /// <param name="target">target data.</param>
    /// <param name="length">target length.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Clear(void* target, int length)
    {
        var targetP = (byte*)target;

        while (length >= sizeof(ulong))
        {
            *(ulong*)targetP = 0;
            targetP += sizeof(ulong);
            length -= sizeof(ulong);
        }

        if (length >= sizeof(uint))
        {
            *(uint*)targetP = 0;
            targetP += sizeof(uint);
            length -= sizeof(uint);
        }

        if (length >= sizeof(ushort))
        {
            *(ushort*)targetP = 0;
            targetP += sizeof(ushort);
            length -= sizeof(ushort);
        }

        if (length > 0)
        {
            *targetP = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Rotl64(ulong val, int shift) => shift == 0 ? val : (val << shift) | (val >> (64 - shift));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Sha3_round(Span<ulong> t, ReadOnlySpan<ulong> a, ulong rc)
    {
        ulong c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        ulong c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        ulong c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        ulong c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        ulong c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

        ulong d0 = Rotl64(c0, 1) ^ c3;
        ulong d1 = Rotl64(c1, 1) ^ c4;
        ulong d2 = Rotl64(c2, 1) ^ c0;
        ulong d3 = Rotl64(c3, 1) ^ c1;
        ulong d4 = Rotl64(c4, 1) ^ c2;

        ulong b00 = a[0] ^ d1;
        ulong b01 = Rotl64(a[6] ^ d2, 44);
        ulong b02 = Rotl64(a[12] ^ d3, 43);
        ulong b03 = Rotl64(a[18] ^ d4, 21);
        ulong b04 = Rotl64(a[24] ^ d0, 14);
        t[0] = b00 ^ (~b01 & b02) ^ rc;
        t[1] = b01 ^ (~b02 & b03);
        t[2] = b02 ^ (~b03 & b04);
        t[3] = b03 ^ (~b04 & b00);
        t[4] = b04 ^ (~b00 & b01);

        ulong b05 = Rotl64(a[3] ^ d4, 28);
        ulong b06 = Rotl64(a[9] ^ d0, 20);
        ulong b07 = Rotl64(a[10] ^ d1, 3);
        ulong b08 = Rotl64(a[16] ^ d2, 45);
        ulong b09 = Rotl64(a[22] ^ d3, 61);
        t[5] = b05 ^ (~b06 & b07);
        t[6] = b06 ^ (~b07 & b08);
        t[7] = b07 ^ (~b08 & b09);
        t[8] = b08 ^ (~b09 & b05);
        t[9] = b09 ^ (~b05 & b06);

        ulong b10 = Rotl64(a[1] ^ d2, 1);
        ulong b11 = Rotl64(a[7] ^ d3, 6);
        ulong b12 = Rotl64(a[13] ^ d4, 25);
        ulong b13 = Rotl64(a[19] ^ d0, 8);
        ulong b14 = Rotl64(a[20] ^ d1, 18);
        t[10] = b10 ^ (~b11 & b12);
        t[11] = b11 ^ (~b12 & b13);
        t[12] = b12 ^ (~b13 & b14);
        t[13] = b13 ^ (~b14 & b10);
        t[14] = b14 ^ (~b10 & b11);

        ulong b15 = Rotl64(a[4] ^ d0, 27);
        ulong b16 = Rotl64(a[5] ^ d1, 36);
        ulong b17 = Rotl64(a[11] ^ d2, 10);
        ulong b18 = Rotl64(a[17] ^ d3, 15);
        ulong b19 = Rotl64(a[23] ^ d4, 56);
        t[15] = b15 ^ (~b16 & b17);
        t[16] = b16 ^ (~b17 & b18);
        t[17] = b17 ^ (~b18 & b19);
        t[18] = b18 ^ (~b19 & b15);
        t[19] = b19 ^ (~b15 & b16);

        ulong b20 = Rotl64(a[2] ^ d3, 62);
        ulong b21 = Rotl64(a[8] ^ d4, 55);
        ulong b22 = Rotl64(a[14] ^ d0, 39);
        ulong b23 = Rotl64(a[15] ^ d1, 41);
        ulong b24 = Rotl64(a[21] ^ d2, 2);
        t[20] = b20 ^ (~b21 & b22);
        t[21] = b21 ^ (~b22 & b23);
        t[22] = b22 ^ (~b23 & b24);
        t[23] = b23 ^ (~b24 & b20);
        t[24] = b24 ^ (~b20 & b21);
    }

    private void Permute(Span<ulong> a)
    {
        Span<ulong> t = stackalloc ulong[25];
        for (var i = 0; i != 24; i += 2)
        {
            this.Sha3_round(t, a, RoundConstants[i + 0]);
            this.Sha3_round(a, t, RoundConstants[i + 1]);
        }
    }
}
