// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
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
        GroupOperations.ge_scalarmult_base(out A, hash, 0);
        GroupOperations.ge_p3_tobytes(publicKey, 0, ref A);

        publicKey.CopyTo(expandedPrivateKey.Slice(32));

        hash.Clear();
    }

    public static void crypto_sign2(
            byte[] sign,
            byte[] message,
            byte[] expandedPrivateKey)
    {
        byte[] az;
        byte[] r;
        byte[] hram;
        GroupElementP3 R;
        var hasher = new Sha512();
        {
            hasher.Update(expandedPrivateKey, 0, 32);
            az = hasher.Finish();
            ScalarOperations.sc_clamp(az, 0);

            hasher.Init();
            hasher.Update(az, 32, 32);
            hasher.Update(message, 0, message.Length);
            r = hasher.Finish();

            ScalarOperations.sc_reduce(r);
            GroupOperations.ge_scalarmult_base(out R, r, 0);
            GroupOperations.ge_p3_tobytes(sign, 0, ref R);

            hasher.Init();
            hasher.Update(sign, 0, 32);
            hasher.Update(expandedPrivateKey, 32, 32);
            hasher.Update(message, 0, message.Length);
            hram = hasher.Finish();

            ScalarOperations.sc_reduce(hram);
            var s = new byte[32];
            Array.Copy(sign, 0 + 32, s, 0, 32);
            ScalarOperations.sc_muladd(s, hram, az, r);
            Array.Copy(s, 0, sign, 0 + 32, 32);
            s.AsSpan().Clear();
        }
    }
}
