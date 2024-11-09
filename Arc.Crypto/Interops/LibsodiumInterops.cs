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

    /*private static bool initialized;

#pragma warning disable CA2255 // The 'ModuleInitializer' attribute should not be used in libraries
    [ModuleInitializer]
#pragma warning restore CA2255 // The 'ModuleInitializer' attribute should not be used in libraries
    public static void Initialize()
    {
        if (!initialized)
        {
            initialized = true;
            sodium_init();
        }
    }

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_init();*/

    #region crypto_secretbox

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void crypto_secretbox_keygen(scoped Span<byte> key);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_secretbox_easy(Span<byte> c, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> k);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_secretbox_open_easy(Span<byte> m, ReadOnlySpan<byte> c, ulong clen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> k);

    #endregion

    #region crypto_box

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_box_keypair(Span<byte> pk, Span<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_box_seed_keypair(Span<byte> pk, Span<byte> sk, ReadOnlySpan<byte> seed);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_box_easy(Span<byte> c, ReadOnlySpan<byte> m, ulong mlen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> sk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_box_open_easy(Span<byte> m, ReadOnlySpan<byte> c, ulong clen, ReadOnlySpan<byte> n, ReadOnlySpan<byte> pk, ReadOnlySpan<byte> sk);

    #endregion

    #region crypto_sign

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_seed_keypair(scoped Span<byte> pk, scoped Span<byte> sk, scoped ReadOnlySpan<byte> seed);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_keypair(scoped Span<byte> pk, scoped Span<byte> sk);

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
    internal static partial int crypto_sign_ed25519_pk_to_curve25519(Span<byte> x25519_pk, ReadOnlySpan<byte> ed25519_pk);

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_sk_to_curve25519(Span<byte> x25519_sk, ReadOnlySpan<byte> ed25519_sk);

    #endregion

    #region hash

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

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_hash(scoped Span<byte> @out, scoped ReadOnlySpan<byte> @in, ulong inlen);

    #endregion
}
