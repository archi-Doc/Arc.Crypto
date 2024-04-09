// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Arc.Crypto;

public static class CryptoHelper
{
    public static bool TryParseFromEnvironmentVariable<T>(string variable, [MaybeNullWhen(false)] out T value)
        where T : IStringConvertible<T>
    {
        if (Environment.GetEnvironmentVariable(variable) is { } source)
        {
            return T.TryParse(source, out value);
        }
        else
        {
            value = default;
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
        var destination = length <= 1024 ? stackalloc char[length] : new char[length];
        if (obj.TryFormat(destination, out var written))
        {
            return new string(destination.Slice(0, written));
        }
        else
        {
            return string.Empty;
        }
    }
}
