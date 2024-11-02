// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;

namespace Arc.Crypto.Ed25519;

#pragma warning disable SA1300 // Element should begin with upper-case letter
#pragma warning disable SA1312 // Variable names should begin with lower-case letter

internal static class Ed25519Operations
{
    public static void CreateKeyFromSeed(ReadOnlySpan<byte> seed, Span<byte> publicKey, Span<byte> expandedPrivateKey)
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

    public static void Sign(Span<byte> sign, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expandedPrivateKey)
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

    public static bool crypto_sign_verify(ReadOnlySpan<byte> sig, ReadOnlySpan<byte> m, ReadOnlySpan<byte> pk)
    {
        Span<byte> h = stackalloc byte[64];
        Span<byte> checkr = stackalloc byte[32];
        GroupElementP3 A;
        GroupElementP2 R;

        if ((sig[63] & 224) != 0)
        {
            return false;
        }

        if (GroupOperations.ge_frombytes_negate_vartime(out A, pk) != 0)
        {
            return false;
        }

        var hasher = new Sha512();
        hasher.Update(sig, 0, 32);
        hasher.Update(pk, 0, 32);
        hasher.Update(m, 0, m.Length);
        h = hasher.Finish();

        ScalarOperations.sc_reduce(h);

        Span<byte> sm32 = stackalloc byte[32];
        sig.Slice(32).CopyTo(sm32);
        GroupOperations.ge_double_scalarmult_vartime(out R, h, ref A, sm32);
        GroupOperations.ge_tobytes(checkr, 0, ref R);
        var result = CryptoBytes.ConstantTimeEquals(checkr, 0, sig, 0, 32);
        h.Clear();
        checkr.Clear();

        return result;
    }
}
