// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

#pragma warning disable SA1405

namespace Arc.Crypto;

public static class Id128Helper
{
    public static Int128 Create()
        => Create(DateTimeOffset.UtcNow);

    public static unsafe Int128 Create(DateTimeOffset dateTimeOffset)
    {
        Span<byte> span = stackalloc byte[16];

        var timestamp = dateTimeOffset.ToUnixTimeMilliseconds();
        new ReadOnlySpan<byte>((byte*)&timestamp, 6).CopyTo(span.Slice(10));

        RandomNumberGenerator.Fill(span.Slice(0, 10));

        return Unsafe.ReadUnaligned<Int128>(ref MemoryMarshal.GetReference(span));
    }
}
