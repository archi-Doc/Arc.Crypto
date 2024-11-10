﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Text;

#pragma warning disable SA1405

namespace Arc.Crypto;

public static class CryptoHelper
{
    private const int StackallocThreshold = 1024;

    private const int P1 = 10;
    private const int P2 = 100;
    private const int P3 = 1000;
    private const int P4 = 10000;
    private const int P5 = 100000;
    private const int P6 = 1000000;
    private const int P7 = 10000000;
    private const int P8 = 100000000;
    private const int P9 = 1000000000;
    private const long P10 = 10000000000;
    private const long P11 = 100000000000;
    private const long P12 = 1000000000000;
    private const long P13 = 10000000000000;
    private const long P14 = 100000000000000;
    private const long P15 = 1000000000000000;
    private const long P16 = 10000000000000000;
    private const long P17 = 100000000000000000;
    private const long P18 = 1000000000000000000;

    [DoesNotReturn]
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowSizeMismatchException(string argumentName, int size)
    {
        throw new ArgumentOutOfRangeException($"The {nameof(argumentName)} length must be {size} bytes.");
    }

    public static ReadOnlySpan<byte> TrimAtFirstNull(ReadOnlySpan<byte> utf8)
    {
        var firstNull = utf8.IndexOf((byte)0);
        if (firstNull < 0)
        {
            return utf8;
        }
        else
        {
            return utf8.Slice(0, firstNull);
        }
    }

    public static byte[] TrimAtFirstNull(byte[] utf8)
    {
        var firstNull = Array.IndexOf(utf8, (byte)0);
        if (firstNull < 0)
        {
            return utf8;
        }
        else
        {
            var trimmed = new byte[firstNull];
            Array.Copy(utf8, trimmed, firstNull);
            return trimmed;
        }
    }

#pragma warning disable SA1503 // Braces should not be omitted

        /// <summary>
        /// Gets the length of the string representation of the specified number.
        /// </summary>
        /// <param name="number">The number to get the string length for.</param>
        /// <returns>The length of the string representation of the number.</returns>
    public static int GetStringLength(int number)
    {
        int add = 0;
        if (number < 0)
        {
            add = 1;
            number = -number;
        }

        // 1,2,3,4,5,6,7,8,9,10
        if (number < P4)
        {// 1,2,3,4
            if (number < P2)
            {// 1,2
                if (number < P1) return 1 + add;
                else return 2 + add;
            }
            else
            {// 3,4
                if (number < P3) return 3 + add;
                else return 4 + add;
            }
        }
        else
        {// 5,6,7,8,9,10
            if (number < P6)
            {// 5,6
                if (number < P5) return 5 + add;
                else return 6 + add;
            }
            else
            {// 7,8,9,10
                if (number < P8)
                {// 7,8
                    if (number < P7) return 7 + add;
                    else return 8 + add;
                }
                else
                {// 9,10
                    if (number < P9) return 9 + add;
                    else return 10 + add;
                }
            }
        }
    }

    /// <summary>
    /// Gets the length of the string representation of the specified number.
    /// </summary>
    /// <param name="number">The number to get the string length for.</param>
    /// <returns>The length of the string representation of the number.</returns>
    public static int GetStringLength(long number)
    {
        int add = 0;
        if (number < 0)
        {
            add = 1;
            number = -number;
        }

        // 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
        if (number < P8)
        {// 1,2,3,4,5,6,7, 8
            if (number < P4)
            {// 1,2,3,4
                if (number < P2)
                {// 1,2
                    if (number < P1) return 1 + add;
                    else return 2 + add;
                }
                else
                {// 3,4
                    if (number < P3) return 3 + add;
                    else return 4 + add;
                }
            }
            else
            {// 5,6,7,8
                if (number < P6)
                {// 5, 6
                    if (number < P5) return 5 + add;
                    else return 6 + add;
                }
                else
                {// 7, 8
                    if (number < P7) return 7 + add;
                    else return 8 + add;
                }
            }
        }
        else
        {// 9,10,11,12,13,14,15,16,17,18,19
            if (number < P12)
            {// 9,10,11,12
                if (number < P10)
                {// 9, 10
                    if (number < P9) return 9 + add;
                    else return 10 + add;
                }
                else
                {// 11, 12
                    if (number < P11) return 11 + add;
                    else return 12 + add;
                }
            }
            else
            {// 13,14,15,16,17,18,19
                if (number < P15)
                {// 13,14,15
                    if (number < P13)
                    {// 13
                        return 13 + add;
                    }
                    else
                    {// 14, 15
                        if (number < P14) return 14 + add;
                        else return 15 + add;
                    }
                }
                else
                {// 16,17,18,19
                    if (number < P17)
                    {// 16, 17
                        if (number < P16) return 16 + add;
                        else return 17 + add;
                    }
                    else
                    {// 18, 19
                        if (number < P18) return 18 + add;
                        else return 19 + add;
                    }
                }
            }
        }
    }
#pragma warning restore SA1503 // Braces should not be omitted

    /// <summary>
    /// Parses the value from the provided source or environment variable and assigns it to the <paramref name="instance"/> parameter.
    /// </summary>
    /// <typeparam name="T">The type of the value to parse.</typeparam>
    /// <param name="source">The source value to parse.</param>
    /// <param name="variable">The name of the environment variable to check if the source value is empty.</param>
    /// <param name="instance">When this method returns, contains the parsed value if successful; otherwise, the default value of <typeparamref name="T"/>.</param>
    /// <returns><c>true</c> if the value was successfully parsed; otherwise, <c>false</c>.</returns>
    public static bool TryParseFromSourceOrEnvironmentVariable<T>(ReadOnlySpan<char> source, string variable, [MaybeNullWhen(false)] out T instance)
        where T : IStringConvertible<T>
    {
        // 1st Source
        if (T.TryParse(source, out instance!))
        {// source.Length > 0 &&
            return true;
        }

        // 2nd: Environment variable
        if (Environment.GetEnvironmentVariable(variable) is { } source2)
        {
            if (T.TryParse(source2, out instance!))
            {
                return true;
            }
        }

        instance = default;
        return false;
    }

    /// <summary>
    /// Parses the value from the provided environment variable and assigns it to the <paramref name="instance"/> parameter.
    /// </summary>
    /// <typeparam name="T">The type of the value to parse.</typeparam>
    /// <param name="variable">The name of the environment variable to check if the source value is empty.</param>
    /// <param name="instance">When this method returns, contains the parsed value if successful; otherwise, the default value of <typeparamref name="T"/>.</param>
    /// <returns><c>true</c> if the value was successfully parsed; otherwise, <c>false</c>.</returns>
    public static bool TryParseFromEnvironmentVariable<T>(string variable, [MaybeNullWhen(false)] out T instance)
        where T : IStringConvertible<T>
    {
        if (Environment.GetEnvironmentVariable(variable) is { } source)
        {
            return T.TryParse(source, out instance);
        }
        else
        {
            instance = default;
            return false;
        }
    }

    [SkipLocalsInit]
    public static string ConvertToString<T>(this T obj)
        where T : IStringConvertible<T>
    { // MemoryMarshal.CreateSpan<char>(ref MemoryMarshal.GetReference(str.AsSpan()), str.Length);
        var length = -1;
        try
        {
            length = obj.GetStringLength();
        }
        catch
        {
        }

        if (length < 0)
        {
            try
            {
                length = T.MaxStringLength;
            }
            catch
            {
            }
        }

        if (length < 0)
        {
            return string.Empty;
        }

        // scoped Span<char> destination;
        var destination = length <= StackallocThreshold ? stackalloc char[length] : new char[length];
        if (obj.TryFormat(destination, out var written))
        {
            return new string(destination.Slice(0, written));
        }
        else
        {
            return string.Empty;
        }
    }

    [SkipLocalsInit]
    public static byte[] ConvertToUtf8<T>(this T obj)
        where T : IStringConvertible<T>
    { // MemoryMarshal.CreateSpan<char>(ref MemoryMarshal.GetReference(str.AsSpan()), str.Length);
        var length = -1;
        try
        {
            length = obj.GetStringLength();
        }
        catch
        {
        }

        if (length < 0)
        {
            try
            {
                length = T.MaxStringLength;
            }
            catch
            {
            }
        }

        if (length < 0)
        {
            return Array.Empty<byte>();
        }

        // scoped Span<char> destination;
        try
        {
            var destination = length <= StackallocThreshold ? stackalloc char[length] : new char[length];
            if (obj.TryFormat(destination, out var written))
            {
                var d = destination.Slice(0, written);
                var count = Encoding.UTF8.GetByteCount(d);
                var array = new byte[count];
                length = Encoding.UTF8.GetBytes(d, array);
                Debug.Assert(length == array.Length);
                return array;
            }
        }
        catch
        {
        }

        return Array.Empty<byte>();
    }
}
