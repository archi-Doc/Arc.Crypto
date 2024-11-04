// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Arc.Crypto.Ed25519;

internal static partial class LibsodiumInterops
{
    internal const string Name = "libsodium";

    [LibraryImport(Name)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_seed_keypair(Span<byte> pk, Span<byte> sk, ReadOnlySpan<byte> seed);
}
