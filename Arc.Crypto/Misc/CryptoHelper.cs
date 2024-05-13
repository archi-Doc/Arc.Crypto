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
        if (source.Length > 0 && T.TryParse(source, out instance!))
        {
            return true;
        }

        // 2nd: Environment variable
        if (Environment.GetEnvironmentVariable(variable) is { } source2)
        {
            if (source2.Length > 0 && T.TryParse(source2, out instance!))
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
        int length = 0;
        try
        {
            length = obj.GetStringLength();
        }
        catch
        {
        }

        if (length == 0)
        {
            try
            {
                length = T.MaxStringLength;
            }
            catch
            {
            }
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
        int length = 0;
        try
        {
            length = obj.GetStringLength();
        }
        catch
        {
        }

        if (length == 0)
        {
            try
            {
                length = T.MaxStringLength;
            }
            catch
            {
            }
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
