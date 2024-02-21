// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;

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
}
