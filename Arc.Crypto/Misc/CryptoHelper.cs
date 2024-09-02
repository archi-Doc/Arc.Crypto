// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
    private const int N2 = -10;
    private const int N3 = -100;
    private const int N4 = -1000;
    private const int N5 = -10000;
    private const int N6 = -100000;
    private const int N7 = -1000000;
    private const int N8 = -10000000;
    private const int N9 = -100000000;
    private const int N10 = -1000000000;

#pragma warning disable SA1503 // Braces should not be omitted
    public static int GetStringLength(int number)
    {
        if (number >= 0)
        {// 1,2,3,4,5,6,7,8,9,10
            if (number < P4)
            {// 1,2,3,4
                if (number < P2)
                {// 1,2
                    if (number < P1) return 1;
                    else return 2;
                }
                else
                {// 3,4
                    if (number < P3) return 3;
                    else return 4;
                }
            }
            else
            {// 5,6,7,8,9,10
                if (number < P6)
                {// 5,6
                    if (number < P5) return 5;
                    else return 6;
                }
                else
                {// 7,8,9,10
                    if (number < P8)
                    {// 7,8
                        if (number < P7) return 7;
                        else return 8;
                    }
                    else
                    {// 9,10
                        if (number < P9) return 9;
                        else return 10;
                    }
                }
            }
        }
        else
        {
            if (number > N5)
            {// 2,3,4,5
                if (number > N3)
                {// 
                    if (number > N2) return 2;
                    else return 3;
                }
                else
                {// 3,4
                    if (number < P3) return 3;
                    else return 4;
                }
            }
            else
            {// 5,6,7,8,9,10
                if (number < P6)
                {// 5,6
                    if (number < P5) return 5;
                    else return 6;
                }
                else
                {// 7,8,9,10
                    if (number < P8)
                    {// 7,8
                        if (number < P7) return 7;
                        else return 8;
                    }
                    else
                    {// 9,10
                        if (number < P9) return 9;
                        else return 10;
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
