// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Diagnostics;

#pragma warning disable SA1405

namespace Arc.Crypto;

/// <summary>
/// Base64 encoding/decoding class.
/// </summary>
public static class Base64
{
    public static class Default
    {
        /// <summary>
        /// Get the length of the base64 encoded data.
        /// </summary>
        /// <param name="sourceLength">The source length.</param>
        /// <returns>The base64 encoded length of <paramref name="sourceLength"/>.</returns>
        public static int GetEncodedLength(int sourceLength)
            => gfoidl.Base64.Base64.Default.GetEncodedLength(sourceLength);

        /// <summary>
        /// Gets the maximum length of the decoded data.
        /// </summary>
        /// <param name="encodedLength">The encoded length.</param>
        /// <returns>The maximum base64 decoded length of <paramref name="encodedLength"/>.</returns>
        public static int GetMaxDecodedLength(int encodedLength)
            => gfoidl.Base64.Base64.Default.GetMaxDecodedLength(encodedLength);

        /// <summary>
        /// Encode from a byte array to a base64 (utf-8) span.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <param name="destination">The destination span of byte (utf-8).<br/>Allocate an array of a length greater than or equal to <seealso cref="GetEncodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the encoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<byte> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Default.Encode(source, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Encode from a byte array to a base64 (utf-16) span.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <param name="destination">The destination span of char (utf-16).<br/>Allocate an array of a length greater than or equal to <seealso cref="GetEncodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the encoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<char> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Default.Encode(source, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Encode from a byte array to a base64 (utf-8) string.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <returns>The base64 (utf-8) string.</returns>
        public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> source)
        {
            var length = gfoidl.Base64.Base64.Default.GetEncodedLength(source.Length);
            var buffer = new byte[length];
            if (gfoidl.Base64.Base64.Default.Encode(source, buffer, out var consumed, out var written) != OperationStatus.Done)
            {
                Array.Empty<byte>();
            }

            Debug.Assert(written == length);
            return buffer;
        }

        /// <summary>
        /// Encode from a byte array to a base64 (utf-16) string.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <returns>The base64 (utf-16) string.</returns>
        public static string FromByteArrayToString(ReadOnlySpan<byte> source)
            => gfoidl.Base64.Base64.Default.Encode(source);

        /// <summary>
        /// Decode from a base64 (utf-8) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-8) string.</param>
        /// <param name="destination">The destination span of byte.<br/>Allocate an array of a length greater than or equal to <seealso cref="GetMaxDecodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the decoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromUtf8ToSpan(ReadOnlySpan<byte> base64, Span<byte> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Default.Decode(base64, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Decode from a base64 (utf-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-16) string.</param>
        /// <param name="destination">The destination span of byte.<br/>Allocate an array of a length greater than or equal to <seealso cref="GetMaxDecodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the decoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromStringToSpan(ReadOnlySpan<char> base64, Span<byte> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Default.Decode(base64, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Decode from a base64 (utf-8) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-8) string.</param>
        /// <returns>The decoded byte array. Returns an empty array if the base64 string is invalid.</returns>
        public static byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> base64)
        {
            try
            {
                var length = gfoidl.Base64.Base64.Default.GetDecodedLength(base64);
                var buffer = new byte[length];
                if (gfoidl.Base64.Base64.Default.Decode(base64, buffer, out var consumed, out var written) != OperationStatus.Done)
                {
                    return Array.Empty<byte>();
                }

                Debug.Assert(written == length);
                return buffer;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Decode from a base64 (utf-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-16).</param>
        /// <returns>The decoded byte array. Returns an empty array if the base64 string is invalid.</returns>
        public static byte[] FromStringToByteArray(ReadOnlySpan<char> base64)
        {
            try
            {
                return gfoidl.Base64.Base64.Default.Decode(base64);
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }
    }

    public static class Url
    {
        /// <summary>
        /// Get the length of the base64 encoded data.
        /// </summary>
        /// <param name="sourceLength">The source length.</param>
        /// <returns>The base64 encoded length of <paramref name="sourceLength"/>.</returns>
        public static int GetEncodedLength(int sourceLength)
            => gfoidl.Base64.Base64.Url.GetEncodedLength(sourceLength);

        /// <summary>
        /// Gets the maximum length of the decoded data.
        /// </summary>
        /// <param name="encodedLength">The encoded length.</param>
        /// <returns>The maximum base64 decoded length of <paramref name="encodedLength"/>.</returns>
        public static int GetMaxDecodedLength(int encodedLength)
            => gfoidl.Base64.Base64.Url.GetMaxDecodedLength(encodedLength);

        /// <summary>
        /// Encode from a byte array to a base64 (utf-8) span.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <param name="destination">The destination span of byte (utf-8).<br/>Allocate an array of a length greater than or equal to <seealso cref="GetEncodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the encoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<byte> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Url.Encode(source, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Encode from a byte array to a base64 (utf-16) span.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <param name="destination">The destination span of char (utf-16).<br/>Allocate an array of a length greater than or equal to <seealso cref="GetEncodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the encoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromByteArrayToSpan(ReadOnlySpan<byte> source, Span<char> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Url.Encode(source, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Encode from a byte array to a base64 (utf-8) string.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <returns>The base64 (utf-8) string.</returns>
        public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> source)
        {
            var length = gfoidl.Base64.Base64.Url.GetEncodedLength(source.Length);
            var buffer = new byte[length];
            if (gfoidl.Base64.Base64.Url.Encode(source, buffer, out var consumed, out var written) != OperationStatus.Done)
            {
                Array.Empty<byte>();
            }

            Debug.Assert(written == length);
            return buffer;
        }

        /// <summary>
        /// Encode from a byte array to a base64 (utf-16) string.
        /// </summary>
        /// <param name="source">The source byte array.</param>
        /// <returns>The base64 (utf-16) string.</returns>
        public static string FromByteArrayToString(ReadOnlySpan<byte> source)
            => gfoidl.Base64.Base64.Url.Encode(source);

        /// <summary>
        /// Decode from a base64 (utf-8) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-8) string.</param>
        /// <param name="destination">The destination span of byte.<br/>Allocate an array of a length greater than or equal to <seealso cref="GetMaxDecodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the decoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromUtf8ToSpan(ReadOnlySpan<byte> base64, Span<byte> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Url.Decode(base64, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Decode from a base64 (utf-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-16) string.</param>
        /// <param name="destination">The destination span of byte.<br/>Allocate an array of a length greater than or equal to <seealso cref="GetMaxDecodedLength(int)"/>.</param>
        /// <param name="written">The number of bytes that were written in destination.</param>
        /// <returns><see langword="true"/> if the decoding was successful; otherwise, <see langword="false"/>.</returns>
        public static bool FromStringToSpan(ReadOnlySpan<char> base64, Span<byte> destination, out int written)
        {
            if (gfoidl.Base64.Base64.Url.Decode(base64, destination, out var consumed, out written) != OperationStatus.Done)
            {
                written = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Decode from a base64 (utf-8) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-8) string.</param>
        /// <returns>The decoded byte array. Returns an empty array if the base64 string is invalid.</returns>
        public static byte[] FromUtf8ToByteArray(ReadOnlySpan<byte> base64)
        {
            try
            {
                var length = gfoidl.Base64.Base64.Url.GetDecodedLength(base64);
                var buffer = new byte[length];
                if (gfoidl.Base64.Base64.Url.Decode(base64, buffer, out var consumed, out var written) != OperationStatus.Done)
                {
                    return Array.Empty<byte>();
                }

                Debug.Assert(written == length);
                return buffer;
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Decode from a base64 (utf-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source base64 (utf-16).</param>
        /// <returns>The decoded byte array. Returns an empty array if the base64 string is invalid.</returns>
        public static byte[] FromStringToByteArray(ReadOnlySpan<char> base64)
        {
            try
            {
                return gfoidl.Base64.Base64.Url.Decode(base64);
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }
    }
}
