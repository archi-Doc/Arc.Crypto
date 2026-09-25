// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Runtime.CompilerServices;

#pragma warning disable SA1402 // File may only contain a single type
#pragma warning disable SA1649 // File name should match first type name

namespace Arc.Crypto;

/// <summary>
/// SHA3-256 Hash Class.
/// </summary>
public class Sha3_256 : Sha3
{
    /// <summary>
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 32;

    /// <summary>
    /// Calculates a hash from the given data and returns it as four 64-bit unsigned integers.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>The 256-bit hash as four 64-bit unsigned integers.</returns>
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) GetHashUInt64(ReadOnlySpan<byte> input)
        => Sha3Helper.Get256UInt64(input);

    /// <summary>
    /// Calculates a hash from the given data and returns it as four 64-bit unsigned integers.
    /// </summary>
    /// <param name="input">The byte array that contains input data.</param>
    /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
    /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
    /// <returns>The 256-bit hash as four 64-bit unsigned integers.</returns>
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) GetHashUInt64(byte[] input, int inputOffset, int inputCount)
        => Sha3Helper.Get256UInt64(input.AsSpan(inputOffset, inputCount));

    /// <summary>
    /// Completes the hash calculation and returns the result as four 64-bit unsigned integers.
    /// </summary>
    /// <returns>The 256-bit hash as four 64-bit unsigned integers.</returns>
    public (ulong Hash0, ulong Hash1, ulong Hash2, ulong Hash3) HashFinalUInt64()
    {
        var state = this.Squeeze();
        var result = (state[0], state[1], state[2], state[3]);
        this.HashInitialize();
        return result;
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
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 48;

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
    /// Length of the hash in bytes.
    /// </summary>
    public const int HashLength = 64;

    /// <inheritdoc/>
    public override string HashName => "SHA3-512";

    /// <inheritdoc/>
    public override uint HashBits => 512;

    /// <inheritdoc/>
    public override bool IsCryptographic => true;
}

/// <summary>
/// Wrapper class for SHA3.<br/>
/// One-shot methods (GetHash) do not affect an incremental calculation in progress.
/// </summary>
public abstract class Sha3 : IHash
{
    private readonly ulong[] state = new ulong[KeccakSpongeStruct.StateLength];
    private int statePosition;

    /// <inheritdoc/>
    public virtual string HashName => "SHA3 Wrapper";

    /// <inheritdoc/>
    public virtual uint HashBits => 0;

    /// <summary>
    /// Gets the number of hash bytes. e.g. 32, 64.
    /// </summary>
    public virtual uint HashBytes => this.HashBits / 8;

    /// <inheritdoc/>
    public virtual bool IsCryptographic => false;

    /// <inheritdoc/>
    public byte[] GetHash(ReadOnlySpan<byte> input)
    {
        var output = new byte[this.HashBytes];
        this.GetHash(input, output);
        return output;
    }

    /// <inheritdoc/>
    public byte[] GetHash(byte[] input, int inputOffset, int inputCount)
        => this.GetHash(input.AsSpan(inputOffset, inputCount));

    /// <summary>
    /// Calculates a hash from the given data and writes it to <paramref name="output"/>.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <param name="output">The span that receives the hash. Its length must be at least <see cref="HashBits"/> / 8.</param>
    [SkipLocalsInit]
    public void GetHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<ulong> state = stackalloc ulong[KeccakSpongeStruct.StateLength];
        var sponge = new KeccakSpongeStruct((int)this.HashBits, state);
        sponge.Absorb(input);
        sponge.SqueezeTo(output);
    }

    /// <inheritdoc/>
    public byte[] HashFinal()
    {
        var output = new byte[this.HashBytes];
        this.HashFinal(output);
        return output;
    }

    /// <summary>
    /// Completes the hash calculation and writes the result to <paramref name="output"/>.
    /// </summary>
    /// <param name="output">The span that receives the hash. Its length must be at least <see cref="HashBits"/> / 8.</param>
    public void HashFinal(Span<byte> output)
    {
        var sponge = new KeccakSpongeStruct((int)this.HashBits, this.state, this.statePosition);
        sponge.SqueezeTo(output);
        this.HashInitialize();
    }

    /// <inheritdoc/>
    public void HashInitialize()
    {
        Array.Clear(this.state);
        this.statePosition = 0;
    }

    /// <inheritdoc/>
    public void HashUpdate(ReadOnlySpan<byte> input)
    {
        var sponge = new KeccakSpongeStruct((int)this.HashBits, this.state, this.statePosition);
        sponge.Absorb(input);
        this.statePosition = sponge.StatePosition;
    }

    /// <inheritdoc/>
    public void HashUpdate(byte[] input, int inputOffset, int inputCount)
        => this.HashUpdate(input.AsSpan(inputOffset, inputCount));

    /// <summary>
    /// Pads and permutes the incremental state; the caller reads the hash words and then reinitializes.
    /// </summary>
    /// <returns>The sponge state, whose leading words hold the hash.</returns>
    private protected ReadOnlySpan<ulong> Squeeze()
    {
        var sponge = new KeccakSpongeStruct((int)this.HashBits, this.state, this.statePosition);
        sponge.Squeeze();
        return this.state;
    }
}
