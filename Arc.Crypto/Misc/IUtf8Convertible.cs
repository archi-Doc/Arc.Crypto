// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Arc.Crypto;

/// <summary>
/// An interface for converting between an object and a utf-8.
/// </summary>
/// <typeparam name="T">The type.</typeparam>
public interface IUtf8Convertible<T>
{
    /// <summary>
    /// Convert a <see cref="byte"/> (utf-8) span to an object.
    /// </summary>
    /// <param name="source">The source utf-8 span.</param>
    /// <param name="instance">An instance of the object converted from the utf-8 span.</param>
    /// <returns><see langword="true"/> if the conversion was successful; otherwise, <see langword="false"/>.</returns>
    static abstract bool TryParse(ReadOnlySpan<byte> source, [MaybeNullWhen(false)] out T? instance);

    /// <summary>
    ///  Get the length of the utf-8 encoded data.
    /// </summary>
    /// <returns>The utf-8 encoded length.</returns>
    int GetUtf8Length();

    /// <summary>
    /// Convert an object to a <see cref="byte"/> (utf-8) span.
    /// </summary>
    /// <param name="destination">The destination span of <see cref="byte"/> (utf-8).<br/>Allocate an array of a length greater than or equal to <seealso cref="GetUtf8Length()"/>.</param>
    /// <param name="written">The number of bytes that were written in destination.</param>
    /// <returns><see langword="true"/> if the conversion was successful; otherwise, <see langword="false"/>.</returns>
    bool TryFormat(Span<byte> destination, out int written);
}
