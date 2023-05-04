// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

public interface IBaseConverter
{
    /// <summary>
    /// Encode a byte array to a UTF-8 string.
    /// </summary>
    /// <param name="bytes">The data to be encoded.</param>
    /// <returns>An encoded UTF-8 string.</returns>
    public byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes);

    /// <summary>
    /// Encode a byte array to a UTF-16 string.
    /// </summary>
    /// <param name="bytes">The data to be encoded.</param>
    /// <returns>An encoded UTF-16 string.</returns>
    public string FromByteArrayToString(ReadOnlySpan<byte> bytes);

    /// <summary>
    /// Decode a UTF-8 string to a byte array.
    /// </summary>
    /// <param name="utf8">The UTF-8 string to be decoded.</param>
    /// <returns>A decoded byte array.</returns>
    public byte[]? FromUtf8ToByteArray(ReadOnlySpan<byte> utf8);

    /// <summary>
    /// Decode a UTF-16 string to a byte array.
    /// </summary>
    /// <param name="utf16">The UTF-16 string to be decoded.</param>
    /// <returns>A decoded byte array.</returns>
    public byte[] FromStringToByteArray(ReadOnlySpan<char> utf16);
}
