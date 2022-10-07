// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;

namespace Arc.Crypto;

/// <summary>
/// Base64 encoding/decoding class.
/// </summary>
public static class Base64
{
    private const int StackallocThreshold = 4096;

    public static class Default
    {
        /// <summary>
        /// Encode from a byte array to a Base64 (UTF-8) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base64 (UTF-8) string.</returns>
        public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
        {
            byte[]? pooledName = null;
            var length = gfoidl.Base64.Base64.Default.GetEncodedLength(bytes.Length);

            scoped Span<byte> span = length <= StackallocThreshold ?
                stackalloc byte[length] :
                (pooledName = ArrayPool<byte>.Shared.Rent(length));

            if (gfoidl.Base64.Base64.Default.Encode(bytes, span, out var consumed, out var written) != OperationStatus.Done)
            {
                if (pooledName != null)
                {
                    ArrayPool<byte>.Shared.Return(pooledName);
                }

                return Array.Empty<byte>();
            }

            var result = span.Slice(0, written).ToArray();
            if (pooledName != null)
            {
                ArrayPool<byte>.Shared.Return(pooledName);
            }

            return result;
        }

        /// <summary>
        /// Encode from a byte array to a Base64 (UTF-16) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base64 (UTF-16) string.</returns>
        public static string FromByteArrayToString(ReadOnlySpan<byte> bytes)
            => gfoidl.Base64.Base64.Default.Encode(bytes);

        /// <summary>
        /// Decode from a Base64 (UTF-8) string to a byte array.
        /// </summary>
        /// <param name="utf8">The source Base64 (UTF-8) string.</param>
        /// <returns>A byte array. Returns null if the Base64 string is invalid.</returns>
        public static byte[]? FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
        {
            byte[]? pooledName = null;
            var length = gfoidl.Base64.Base64.Default.GetDecodedLength(utf8);

            scoped Span<byte> span = length <= StackallocThreshold ?
                stackalloc byte[length] :
                (pooledName = ArrayPool<byte>.Shared.Rent(length));

            if (gfoidl.Base64.Base64.Default.Decode(utf8, span, out var consumed, out var written) != OperationStatus.Done)
            {
                if (pooledName != null)
                {
                    ArrayPool<byte>.Shared.Return(pooledName);
                }

                return null;
            }

            var result = span.Slice(0, written).ToArray();
            if (pooledName != null)
            {
                ArrayPool<byte>.Shared.Return(pooledName);
            }

            return result;
        }

        /// <summary>
        /// Decode from a Base64 (UTF-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source Base64 (UTF-16).</param>
        /// <returns>A Byte array. Returns null if the base64 string is invalid.</returns>
        public static byte[] FromStringToByteArray(string base64)
            => gfoidl.Base64.Base64.Default.Decode(base64);
    }

    public static class Url
    {
        /// <summary>
        /// Encode from a byte array to a Base64 Url (UTF-8) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base64 Url (UTF-8) string.</returns>
        public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
        {
            byte[]? pooledName = null;
            var length = gfoidl.Base64.Base64.Url.GetEncodedLength(bytes.Length);

            scoped Span<byte> span = length <= StackallocThreshold ?
                stackalloc byte[length] :
                (pooledName = ArrayPool<byte>.Shared.Rent(length));

            if (gfoidl.Base64.Base64.Url.Encode(bytes, span, out var consumed, out var written) != OperationStatus.Done)
            {
                if (pooledName != null)
                {
                    ArrayPool<byte>.Shared.Return(pooledName);
                }

                return Array.Empty<byte>();
            }

            var result = span.Slice(0, written).ToArray();
            if (pooledName != null)
            {
                ArrayPool<byte>.Shared.Return(pooledName);
            }

            return result;
        }

        /// <summary>
        /// Encode from a byte array to a Base64 Url (UTF-16) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base64 Url (UTF-16) string.</returns>
        public static string FromByteArrayToString(ReadOnlySpan<byte> bytes)
            => gfoidl.Base64.Base64.Url.Encode(bytes);

        /// <summary>
        /// Decode from a Base64 Url (UTF-8) string to a byte array.
        /// </summary>
        /// <param name="utf8">The source Base64 Url (UTF-8) string.</param>
        /// <returns>A byte array. Returns null if the Base64 string is invalid.</returns>
        public static byte[]? FromUtf8ToByteArray(ReadOnlySpan<byte> utf8)
        {
            byte[]? pooledName = null;
            var length = gfoidl.Base64.Base64.Url.GetDecodedLength(utf8);

            scoped Span<byte> span = length <= StackallocThreshold ?
                stackalloc byte[length] :
                (pooledName = ArrayPool<byte>.Shared.Rent(length));

            if (gfoidl.Base64.Base64.Url.Decode(utf8, span, out var consumed, out var written) != OperationStatus.Done)
            {
                if (pooledName != null)
                {
                    ArrayPool<byte>.Shared.Return(pooledName);
                }

                return null;
            }

            var result = span.Slice(0, written).ToArray();
            if (pooledName != null)
            {
                ArrayPool<byte>.Shared.Return(pooledName);
            }

            return result;
        }

        /// <summary>
        /// Decode from a Base64 Url (UTF-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source Base64 Url (UTF-16).</param>
        /// <returns>A Byte array. Returns null if the base64 string is invalid.</returns>
        public static byte[] FromStringToByteArray(string base64)
            => gfoidl.Base64.Base64.Url.Decode(base64);
    }
}
