// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Arc.Crypto;

#pragma warning disable SA1300 // Element should begin with upper-case letter

internal static partial class LibsodiumInterops
{
    internal const string Name = "libsodium";

    [StructLayout(LayoutKind.Explicit, Size = 384)]
    internal struct crypto_generichash_blake2b_state
    {
    }

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_seed_keypair(Span<byte> pk, Span<byte> sk, ReadOnlySpan<byte> seed);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_detached(Span<byte> sig, out ulong siglen_p, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_verify_detached(ReadOnlySpan<byte> sig, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> pk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_init(ref Ed25519ph state);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_update(ref Ed25519ph state, ReadOnlySpan<byte> m, ulong mlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_final_create(ref Ed25519ph state, Span<byte> sig, out ulong siglen_p, ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_final_verify(ref Ed25519ph state, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> pk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int crypto_generichash_blake2b(Span<byte> @out, nuint outlen, ReadOnlySpan<byte> @in, ulong inlen, IntPtr key, nuint keylen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash_blake2b_init(ref crypto_generichash_blake2b_state state, IntPtr key, nuint keylen, nuint outlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash_blake2b_update(ref crypto_generichash_blake2b_state state, ReadOnlySpan<byte> @in, ulong inlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash_blake2b_final(ref crypto_generichash_blake2b_state state, Span<byte> @out, nuint outlen);
}
