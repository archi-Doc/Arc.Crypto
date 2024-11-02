// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1300 // Element should begin with upper-case letter
#pragma warning disable SA1312 // Variable names should begin with lower-case letter

internal static class Ed25519Operations
{
    public static void crypto_sign_keypair(ReadOnlySpan<byte> seed, Span<byte> publicKey, Span<byte> expandedPrivateKey)
    {
        seed.CopyTo(expandedPrivateKey);

        Span<byte> hash = stackalloc byte[64];
        Sha2Helper.Get512_Span(seed, hash);

        ScalarOperations.sc_clamp(hash, 0);

        GroupElementP3 A;
        GroupOperations.ge_scalarmult_base(out A, hash);
        GroupOperations.ge_p3_tobytes(publicKey, ref A);

        publicKey.CopyTo(expandedPrivateKey.Slice(32));

        hash.Clear();
    }

    public static void crypto_sign2(Span<byte> sign, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expandedPrivateKey)
    {
        Span<byte> az = stackalloc byte[64];
        Span<byte> r = stackalloc byte[64];
        Span<byte> hram = stackalloc byte[64];
        GroupElementP3 R;

        var incrementalHash = Sha2Helper.IncrementalSha512Pool.Get();
        try
        {
            incrementalHash.AppendData(expandedPrivateKey.Slice(0, 32));
            incrementalHash.GetHashAndReset(az);
            ScalarOperations.sc_clamp(az, 0);

            incrementalHash.AppendData(az.Slice(32, 32));
            incrementalHash.AppendData(message);
            incrementalHash.GetHashAndReset(r);

            ScalarOperations.sc_reduce(r);
            GroupOperations.ge_scalarmult_base(out R, r);
            GroupOperations.ge_p3_tobytes(sign, ref R);

            incrementalHash.AppendData(sign.Slice(0, 32));
            incrementalHash.AppendData(expandedPrivateKey.Slice(32, 32));
            incrementalHash.AppendData(message);
            incrementalHash.GetHashAndReset(hram);

            ScalarOperations.sc_reduce(hram);
            Span<byte> s = stackalloc byte[32];

            sign.Slice(32).CopyTo(s);
            ScalarOperations.sc_muladd(s, hram, az, r);
            s.CopyTo(sign.Slice(32));
            s.Clear();
        }
        finally
        {
            Sha2Helper.IncrementalSha512Pool.Return(incrementalHash);
        }
    }
}
