// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

#pragma warning disable SA1405

namespace Arc.Crypto;

public static class Base32Sort
{
    public static class Reference
    {
        /// <summary>
        /// Encode from a byte array to a Base32Sort (UTF-8) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base32Sort (UTF-8) string.</returns>
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
        /// Encode from a byte array to a Base32Sort (UTF-16) string.
        /// </summary>
        /// <param name="bytes">The source byte array.</param>
        /// <returns>A Base32Sort (UTF-16) string.</returns>
        public static string FromByteArrayToString(ReadOnlySpan<byte> bytes)
            => Base32SortReference.FromByteArrayToString(bytes);

        /// <summary>
        /// Decode from a Base32Sort (UTF-8) string to a byte array.
        /// </summary>
        /// <param name="utf8">The source Base32Sort (UTF-8) string.</param>
        /// <returns>A byte array. Returns null if the Base32Sort string is invalid.</returns>
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
        /// Decode from a Base32Sort (UTF-16) string to a byte array.
        /// </summary>
        /// <param name="base32Sort">The source Base32Sort (UTF-16).</param>
        /// <returns>A Byte array. Returns null if the string is invalid.</returns>
        public static byte[] FromStringToByteArray(ReadOnlySpan<char> base32Sort)
            => Base32SortReference.FromStringToByteArray(base32Sort);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetEncodedLength(int length)
        => ((length << 3) + 4) / 5;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetDecodedLength(int length)
        => (length * 5) >> 3;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FastMod5(int value)
    {
        if (Environment.Is64BitProcess)
        {
            ulong lowbits = ((ulong.MaxValue / 5) + 1) * (uint)value;
            uint highbits = (uint)Math.BigMul(lowbits, 5, out _);
            return (int)highbits;
        }
        else
        {
            return value % 5;
        }
    }
}
