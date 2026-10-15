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
    /// Gets the hash size in bits, such as 256 or 512.
    /// </summary>
    uint HashBits { get; }

    /// <summary>
    /// Gets a value indicating whether the hash algorithm is cryptographic.
    /// </summary>
    bool IsCryptographic { get; }

    /// <summary>
    /// Computes the hash of the given data in one shot.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    /// <returns>A new array that contains the hash.</returns>
    /// <remarks>
    /// Whether this affects an incremental calculation in progress depends on the implementation.
    /// </remarks>
    byte[] GetHash(ReadOnlySpan<byte> input);

    /// <summary>
    /// Computes the hash of the given data in one shot.
    /// </summary>
    /// <param name="input">The byte array that contains input data.</param>
    /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
    /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
    /// <returns>A new array that contains the hash.</returns>
    /// <remarks>
    /// Whether this affects an incremental calculation in progress depends on the implementation.
    /// </remarks>
    byte[] GetHash(byte[] input, int inputOffset, int inputCount);

    /// <summary>
    /// Resets the state. Call before each incremental calculation, append data with HashUpdate,
    /// then retrieve the result with HashFinal.
    /// </summary>
    void HashInitialize();

    /// <summary>
    /// Appends data to the incremental calculation.
    /// </summary>
    /// <param name="input">The read-only span that contains input data.</param>
    void HashUpdate(ReadOnlySpan<byte> input);

    /// <summary>
    /// Appends data to the incremental calculation.
    /// </summary>
    /// <param name="input">The byte array that contains input data.</param>
    /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
    /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
    void HashUpdate(byte[] input, int inputOffset, int inputCount);

    /// <summary>
    /// Returns the hash of all appended data as a new array. Reset behavior varies by implementation;
    /// call HashInitialize before starting another calculation.
    /// </summary>
    /// <returns>A new array that contains the hash.</returns>
    byte[] HashFinal();
}
