// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

public interface IBase32Converter
{
    /// <summary>
    /// Encode from a byte array to a base32 (utf-8) span.
    /// </summary>
    /// <param name="source">The source byte array.</param>
    /// <param name="destination">The destination span of byte (utf-8).<br/>Allocate an array of a length greater than or equal to <seealso cref="Base32Sort.GetEncodedLength(int)"/>.</param>
    /// <param name="written">The number of bytes that were written in destination.</param>
    /// <returns><see langword="true"/> if the encoding was successful; otherwise, <see langword="false"/>.</returns>
    public bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<byte> destination, out int written);

    /// <summary>
    /// Encode from a byte array to a base32 (utf-16) span.
    /// </summary>
    /// <param name="source">The source byte array.</param>
    /// <param name="destination">The destination span of char (utf-16).<br/>Allocate an array of a length greater than or equal to <seealso cref="Base32Sort.GetEncodedLength(int)"/>.</param>
    /// <param name="written">The number of bytes that were written in destination.</param>
    /// <returns><see langword="true"/> if the encoding was successful; otherwise, <see langword="false"/>.</returns>
    public bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<char> destination, out int written);

    /// <summary>
    /// Encode from a byte array to a base32 (utf-8) string.
    /// </summary>
    /// <param name="source">The data to be encoded.</param>
    /// <returns>An encoded utf-8 string.</returns>
    public byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> source);

    /// <summary>
    /// Encode from a byte array to a base32 (utf-16) string.
    /// </summary>
    /// <param name="source">The data to be encoded.</param>
    /// <returns>An encoded utf-16 string.</returns>
    public string FromByteArrayToString(ReadOnlySpan<byte> source);

    /// <summary>
    /// Decode from a base32 (utf-8) string to a byte array.
    /// </summary>
    /// <param name="base32">The source base32 (utf-8) string.</param>
    /// <returns>The decoded byte array. Returns an empty array if the base32 string is invalid.</returns>
    public byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> base32);

    /// <summary>
    /// Decode from a base32 (utf-16) string to a byte array.
    /// </summary>
    /// <param name="base32">The source base32 (utf-16) string.</param>
    /// <returns>The decoded byte array. Returns an empty array if the base32 string is invalid.</returns>
    public byte[] FromStringToByteArray(ReadOnlySpan<char> base32);
}
