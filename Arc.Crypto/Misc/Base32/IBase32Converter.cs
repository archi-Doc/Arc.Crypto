// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;

namespace Arc.Crypto;

/// <summary>
/// Converts between bytes and Base32 text as UTF-8 bytes or UTF-16 characters.
/// </summary>
public interface IBase32Converter
{
    /// <summary>
    /// Encodes bytes into Base32 text as UTF-8 bytes.
    /// </summary>
    /// <param name="source">The bytes to encode.</param>
    /// <param name="destination">The destination for the encoded text. Its length must be at least <see cref="Base32Sort.GetEncodedLength(int)"/> of <c>source.Length</c>.</param>
    /// <param name="written">The number of bytes written, or 0 on failure.</param>
    /// <returns><see langword="true"/> on success; <see langword="false"/> if <paramref name="destination"/> is too small, in which case nothing is written.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The encoded length exceeds <see cref="int.MaxValue"/>.</exception>
    public bool FromBytesToSpan(ReadOnlySpan<byte> source, Span<byte> destination, out int written);

    /// <summary>
    /// Encodes bytes into Base32 text as UTF-16 characters.
    /// </summary>
    /// <param name="source">The bytes to encode.</param>
    /// <param name="destination">The destination for the encoded text. Its length must be at least <see cref="Base32Sort.GetEncodedLength(int)"/> of <c>source.Length</c>.</param>
    /// <param name="written">The number of characters written, or 0 on failure.</param>
    /// <returns><see langword="true"/> on success; <see langword="false"/> if <paramref name="destination"/> is too small, in which case nothing is written.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The encoded length exceeds <see cref="int.MaxValue"/>.</exception>
    public bool FromBytesToSpan(ReadOnlySpan<byte> source, Span<char> destination, out int written);

    /// <summary>
    /// Encodes bytes into a new array of Base32 text as UTF-8 bytes.
    /// </summary>
    /// <param name="source">The bytes to encode.</param>
    /// <returns>A new array holding the encoded text as UTF-8 bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The encoded length exceeds <see cref="int.MaxValue"/>.</exception>
    public byte[] FromBytesToUtf8(ReadOnlySpan<byte> source);

    /// <summary>
    /// Encodes bytes into a Base32 string.
    /// </summary>
    /// <param name="source">The bytes to encode.</param>
    /// <returns>The encoded string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The encoded length exceeds <see cref="int.MaxValue"/>.</exception>
    public string FromBytesToString(ReadOnlySpan<byte> source);

    /// <summary>
    /// Decodes Base32 text given as UTF-8 bytes into a span.
    /// </summary>
    /// <param name="base32">The Base32 text as UTF-8 bytes.</param>
    /// <param name="destination">The destination for the decoded bytes. Its length must be at least <see cref="Base32Sort.GetDecodedLength(int)"/> of <c>base32.Length</c>.</param>
    /// <param name="written">The number of bytes written, or 0 on failure.</param>
    /// <returns><see langword="true"/> on success; <see langword="false"/> if <paramref name="destination"/> is too small (nothing is written)
    /// or <paramref name="base32"/> contains an invalid character (<paramref name="destination"/> may be partially written).</returns>
    /// <remarks>
    /// Trailing bits that do not complete a byte are ignored (see <see cref="Base32Sort"/>).
    /// </remarks>
    public bool FromUtf8ToSpan(ReadOnlySpan<byte> base32, Span<byte> destination, out int written);

    /// <summary>
    /// Decodes Base32 text given as UTF-16 characters into a span.
    /// </summary>
    /// <param name="base32">The Base32 text.</param>
    /// <param name="destination">The destination for the decoded bytes. Its length must be at least <see cref="Base32Sort.GetDecodedLength(int)"/> of <c>base32.Length</c>.</param>
    /// <param name="written">The number of bytes written, or 0 on failure.</param>
    /// <returns><see langword="true"/> on success; <see langword="false"/> if <paramref name="destination"/> is too small (nothing is written)
    /// or <paramref name="base32"/> contains an invalid character (<paramref name="destination"/> may be partially written).</returns>
    /// <remarks>
    /// Trailing bits that do not complete a byte are ignored (see <see cref="Base32Sort"/>). Characters above U+00FF are invalid.
    /// </remarks>
    public bool FromStringToSpan(ReadOnlySpan<char> base32, Span<byte> destination, out int written);

    /// <summary>
    /// Decodes Base32 text given as UTF-8 bytes into a new byte array.
    /// </summary>
    /// <param name="base32">The Base32 text as UTF-8 bytes.</param>
    /// <returns>The decoded bytes, or an empty array if <paramref name="base32"/> contains an invalid character.
    /// Valid input that decodes to no bytes also returns an empty array; use <see cref="FromUtf8ToSpan(ReadOnlySpan{byte}, Span{byte}, out int)"/> to tell the cases apart.</returns>
    /// <remarks>
    /// Trailing bits that do not complete a byte are ignored (see <see cref="Base32Sort"/>).
    /// </remarks>
    public byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> base32);

    /// <summary>
    /// Decodes Base32 text given as UTF-16 characters into a new byte array.
    /// </summary>
    /// <param name="base32">The Base32 text.</param>
    /// <returns>The decoded bytes, or an empty array if <paramref name="base32"/> contains an invalid character.
    /// Valid input that decodes to no bytes also returns an empty array; use <see cref="FromStringToSpan(ReadOnlySpan{char}, Span{byte}, out int)"/> to tell the cases apart.</returns>
    /// <remarks>
    /// Trailing bits that do not complete a byte are ignored (see <see cref="Base32Sort"/>). Characters above U+00FF are invalid.
    /// </remarks>
    public byte[] FromStringToByteArray(ReadOnlySpan<char> base32);
}
