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
        /// Encode from a byte array to a Base64 (UTF-8) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base64 (UTF-8) string.</returns>
        public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
        {
            var length = gfoidl.Base64.Base64.Default.GetEncodedLength(bytes.Length);
            var buffer = new byte[length];
            if (gfoidl.Base64.Base64.Default.Encode(bytes, buffer, out var consumed, out var written) != OperationStatus.Done)
            {
                Array.Empty<byte>();
            }

            Debug.Assert(written == length);
            return buffer;
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
            try
            {
                var length = gfoidl.Base64.Base64.Default.GetDecodedLength(utf8);
                var buffer = new byte[length];
                if (gfoidl.Base64.Base64.Default.Decode(utf8, buffer, out var consumed, out var written) != OperationStatus.Done)
                {
                    return null;
                }

                Debug.Assert(written == length);
                return buffer;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Decode from a Base64 (UTF-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source Base64 (UTF-16).</param>
        /// <returns>A Byte array. Returns null if the base64 string is invalid.</returns>
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
        /// Encode from a byte array to a Base64 Url (UTF-8) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base64 Url (UTF-8) string.</returns>
        public static byte[] FromByteArrayToUtf8(ReadOnlySpan<byte> bytes)
        {
            var length = gfoidl.Base64.Base64.Url.GetEncodedLength(bytes.Length);
            var buffer = new byte[length];
            if (gfoidl.Base64.Base64.Url.Encode(bytes, buffer, out var consumed, out var written) != OperationStatus.Done)
            {
                Array.Empty<byte>();
            }

            Debug.Assert(written == length);
            return buffer;
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
            try
            {
                var length = gfoidl.Base64.Base64.Url.GetDecodedLength(utf8);
                var buffer = new byte[length];
                if (gfoidl.Base64.Base64.Url.Decode(utf8, buffer, out var consumed, out var written) != OperationStatus.Done)
                {
                    return null;
                }

                Debug.Assert(written == length);
                return buffer;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Decode from a Base64 Url (UTF-16) string to a byte array.
        /// </summary>
        /// <param name="base64">The source Base64 Url (UTF-16).</param>
        /// <returns>A Byte array. Returns null if the base64 string is invalid.</returns>
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
