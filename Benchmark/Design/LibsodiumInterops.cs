// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Benchmark;

#pragma warning disable SA1300 // Element should begin with upper-case letter

internal static partial class LibsodiumInterops
{
    internal const string Name = "libsodium";

    [StructLayout(LayoutKind.Explicit, Size = 384)]
    internal struct crypto_generichash_blake2b_state
    {
    }

    private static bool initialized;

#pragma warning disable CA2255 // The 'ModuleInitializer' attribute should not be used in libraries
    [ModuleInitializer]
#pragma warning restore CA2255 // The 'ModuleInitializer' attribute should not be used in libraries
    public static void Initialize()
    {
        if (!initialized)
        {
            initialized = true;
            // sodium_init();
        }
    }

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_init();

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_encrypt(Span<byte> c, out ulong clen_p, ReadOnlySpan<byte> m, ulong mlen, IntPtr ad, ulong adlen, IntPtr nsec, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aegis256_decrypt(Span<byte> m, out ulong mlen_p, IntPtr nsec, ReadOnlySpan<byte> c, ulong clen, IntPtr ad, ulong adlen, ReadOnlySpan<byte> npub, ReadOnlySpan<byte> k);
}
