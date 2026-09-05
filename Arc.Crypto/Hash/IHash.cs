// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

/// <summary>
/// Common one-shot and incremental hashing operations. Instances are not thread-safe.
/// </summary>
public interface IHash
{
    /// <summary>
    /// Gets the algorithm name, such as "CRC-32" or "SHA3-256".
    /// </summary>
    string HashName { get; }

    /// <summary>
    /// Gets the number of hash bits. e.g. 256, 512.
    /// </summary>
    uint HashBits { get; }

    /// <summary>
    /// Gets a value indicating whether the hash algorithm is cryptographic.
    /// </summary>
    bool IsCryptographic { get; }

    /// <summary>
    /// Calculates a hash from the given data.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A hash.</returns>
    byte[] GetHash(ReadOnlySpan<byte> input);

    /// <summary>
    /// Calculates a hash from the given data.
    /// </summary>
    /// <param name="input">The byte array that contains input data.</param>
    /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
    /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
    /// <returns>A hash.</returns>
    byte[] GetHash(byte[] input, int inputOffset, int inputCount);

    /// <summary>
    /// Resets the state. Call before each incremental calculation, append data with HashUpdate,
    /// then retrieve the result with HashFinal.
    /// </summary>
    void HashInitialize();

    /// <summary>
    /// Update hash function state.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    void HashUpdate(ReadOnlySpan<byte> input);

    /// <summary>
    /// Update hash function state.
    /// </summary>
    /// <param name="input">The byte array that contains input data.</param>
    /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
    /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
    void HashUpdate(byte[] input, int inputOffset, int inputCount);

    /// <summary>
    /// Returns the hash of all appended data as a new array. Reset behavior varies by implementation;
    /// call HashInitialize before starting another calculation.
    /// </summary>
    /// <returns>A hash.</returns>
    byte[] HashFinal();
}
