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
    internal static partial int crypto_sign_ed25519_seed_keypair(scoped Span<byte> pk, scoped Span<byte> sk, scoped ReadOnlySpan<byte> seed);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_keypair(scoped Span<byte> pk, scoped Span<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_sk_to_seed(scoped Span<byte> seed, scoped ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_sk_to_pk(scoped Span<byte> pk, scoped ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_detached(scoped Span<byte> sig, out ulong siglen_p, scoped ReadOnlySpan<byte> m, ulong mlen, scoped ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_verify_detached(scoped ReadOnlySpan<byte> sig, scoped ReadOnlySpan<byte> m, ulong mlen, scoped ReadOnlySpan<byte> pk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_init(ref Ed25519ph state);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_update(ref Ed25519ph state, scoped ReadOnlySpan<byte> m, ulong mlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_final_create(ref Ed25519ph state, scoped Span<byte> sig, out ulong siglen_p, scoped ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519ph_final_verify(ref Ed25519ph state, scoped ReadOnlySpan<byte> sig, scoped ReadOnlySpan<byte> pk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial int crypto_generichash_blake2b(Span<byte> @out, nuint outlen, scoped ReadOnlySpan<byte> @in, ulong inlen, IntPtr key, nuint keylen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash_blake2b_init(ref crypto_generichash_blake2b_state state, IntPtr key, nuint keylen, nuint outlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash_blake2b_update(ref crypto_generichash_blake2b_state state, scoped ReadOnlySpan<byte> @in, ulong inlen);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash_blake2b_final(ref crypto_generichash_blake2b_state state, scoped Span<byte> @out, nuint outlen);
}
