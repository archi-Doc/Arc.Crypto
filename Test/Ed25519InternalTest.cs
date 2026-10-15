// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Numerics;
using Arc.Crypto;
using Arc.Crypto.Ed25519;
using Xunit;

namespace Test;

/// <summary>
/// The field arithmetic modulo <c>2^255 - 19</c> in <see cref="Ed25519Internal"/>, checked against <see cref="BigInteger"/>.
/// </summary>
public class Ed25519InternalTest
{
    private const ulong Limb51 = (1UL << 51) - 1;
    private const ulong Limb53 = (1UL << 53) - 1;

    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger Two255 = BigInteger.One << 255;
    private static readonly BigInteger Two256 = BigInteger.One << 256;

    [Fact]
    public void FromBytesToBytes_Canonicalizes()
    {
        var rng = new Random(25519);
        var values = new BigInteger[]
        {
            0, 1, 18, 19, P - 1, P, P + 1, P + 18, Two255 - 1, Two255, Two255 + 1, Two255 + P, Two256 - 1, Limb51, (BigInteger)Limb51 << 51,
        };

        var output = new byte[32];
        foreach (var v in values)
        {
            Check(v);
        }

        for (var i = 0; i < 1_000; i++)
        {
            Check(RandomBelow(rng, Two256));
        }

        void Check(BigInteger v)
        {
            // Bit 255 is ignored; values in [p, 2^255) are accepted and reduced on output.
            Ed25519Internal.fe25519_frombytes(out var f, ToBytes(v));
            (f.h0 <= Limb51 && f.h1 <= Limb51 && f.h2 <= Limb51 && f.h3 <= Limb51 && f.h4 <= Limb51).IsTrue();
            Value(f).Is(v % Two255);

            Ed25519Internal.fe25519_tobytes(output, ref f);
            FromBytes(output).Is((v % Two255) % P);
        }
    }

    [Fact]
    public void AddSubMulSq_MatchBigInteger()
    {
        var rng = new Random(1955);
        var bytes = new byte[32];
        for (var i = 0; i < 2_000; i++)
        {
            fe25519 a, b;
            if (i < 4)
            {
                // Saturated limbs: all 2^51 - 1 (from the decoder's range) on either side.
                a = (i & 1) == 0 ? new(Limb51, Limb51, Limb51, Limb51, Limb51) : new(1);
                b = (i & 2) == 0 ? new(Limb51, Limb51, Limb51, Limb51, Limb51) : default;
            }
            else
            {
                rng.NextBytes(bytes);
                Ed25519Internal.fe25519_frombytes(out a, bytes);
                rng.NextBytes(bytes);
                Ed25519Internal.fe25519_frombytes(out b, bytes);
            }

            var va = Value(a);
            var vb = Value(b);

            Ed25519Internal.fe25519_add(out var s, ref a, ref b);
            Value(s).Is(va + vb);
            Ed25519Internal.fe25519_sub(out var d, ref a, ref b);
            Mod(Value(d)).Is(Mod(va - vb));

            Ed25519Internal.fe25519_mul(out var m, ref s, ref d);
            CheckReducedLimbs(m);
            Mod(Value(m)).Is(Mod((va + vb) * (va - vb)));

            Ed25519Internal.fe25519_sq(out var q, ref s);
            CheckReducedLimbs(q);
            Mod(Value(q)).Is(Mod((va + vb) * (va + vb)));

            Ed25519Internal.fe25519_mul(out var dd, ref d, ref d);
            Mod(Value(dd)).Is(Mod((va - vb) * (va - vb)));

            // Outputs of mul and sq feed back into mul.
            Ed25519Internal.fe25519_mul(out var mq, ref m, ref q);
            Mod(Value(mq)).Is(Mod(Value(m) * Value(q)));
        }
    }

    /// <summary>
    /// <see cref="Ed25519Internal.fe25519_mul"/> on limbs up to 2^53, the bound every caller relies on, where the column sums
    /// reach about 2^113 and the carries cross the 64-bit halves of the accumulators.
    /// </summary>
    [Fact]
    public void Mul_MatchesBigInteger_UpToLimbBound()
    {
        var rng = new Random(53);
        for (var i = 0; i < 5_000; i++)
        {
            var f = i == 0 ? new fe25519(Limb53, Limb53, Limb53, Limb53, Limb53) : RandomLimbs(rng);
            var g = i < 2 ? new fe25519(Limb53, Limb53, Limb53, Limb53, Limb53) : RandomLimbs(rng);
            Ed25519Internal.fe25519_mul(out var h, ref f, ref g);
            CheckReducedLimbs(h);
            Mod(Value(h)).Is(Mod(Value(f) * Value(g)));
        }
    }

    [Fact]
    public void Invert_MatchesModPow()
    {
        var rng = new Random(2552);
        var bytes = new byte[32];
        var output = new byte[32];
        var values = new BigInteger[] { 0, 1, 2, 19, P - 1, P - 2, (P - 1) / 2 };
        for (var i = 0; i < values.Length + 200; i++)
        {
            fe25519 z;
            if (i < values.Length)
            {
                Ed25519Internal.fe25519_frombytes(out z, ToBytes(values[i]));
            }
            else
            {
                // Differences have limbs above 2^51, as in the key conversion.
                rng.NextBytes(bytes);
                Ed25519Internal.fe25519_frombytes(out var a, bytes);
                rng.NextBytes(bytes);
                Ed25519Internal.fe25519_frombytes(out var b, bytes);
                Ed25519Internal.fe25519_sub(out z, ref a, ref b);
            }

            Ed25519Internal.fe25519_invert(out var inv, ref z);
            Ed25519Internal.fe25519_tobytes(output, ref inv);
            var vz = Mod(Value(z));
            FromBytes(output).Is(BigInteger.ModPow(vz, P - 2, P)); // 0 for z = 0
            if (!vz.IsZero)
            {
                ((FromBytes(output) * vz) % P).IsOne.IsTrue();
            }
        }
    }

    [Fact]
    public void Encoding_RequiresThirtyTwoBytes()
    {
        var f = new fe25519(1);
        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519Internal.fe25519_tobytes(new byte[31], ref f));
        Assert.Throws<ArgumentOutOfRangeException>(() => Ed25519Internal.fe25519_frombytes(out _, new byte[31]));
    }

    /// <summary>
    /// <see cref="CryptoDual"/> computes <c>u = (1 + y) / (1 - y)</c> and <c>y = (u - 1) / (u + 1)</c> with these helpers
    /// and carries bit 255 over unchanged.
    /// </summary>
    [Fact]
    public void CryptoDualConversion_MatchesBigInteger()
    {
        var rng = new Random(7748);
        var input = new byte[32];
        var output = new byte[32];
        var back = new byte[32];
        for (var i = 0; i < 100; i++)
        {
            if (i == 0)
            {
                Array.Clear(input); // y = 0 maps to u = 1 and back.
            }
            else
            {
                rng.NextBytes(input);
            }

            var sign = input[31] & 0x80;
            var v = (FromBytes(input) % Two255) % P;

            CryptoDual.ConvertSignPublicKeyToBox(input, output);
            (output[31] & 0x80).Is(sign);
            var u = FromBytes(output) % Two255;
            u.Is(Mod((1 + v) * BigInteger.ModPow(Mod(1 - v), P - 2, P)));

            CryptoDual.ConvertBoxPublicKeyToSign(output, back);
            (back[31] & 0x80).Is(sign);
            (FromBytes(back) % Two255).Is(Mod((u - 1) * BigInteger.ModPow(Mod(u + 1), P - 2, P)));
            if (i == 0)
            {
                output.Is(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
                back.Is(input);
            }

            CryptoDual.ConvertBoxPublicKeyToSign(input, output);
            (FromBytes(output) % Two255).Is(Mod((v - 1) * BigInteger.ModPow(Mod(v + 1), P - 2, P)));
        }
    }

    private static void CheckReducedLimbs(in fe25519 h)
        => (h.h0 < (1UL << 52) && h.h1 < (1UL << 52) && h.h2 < (1UL << 52) && h.h3 < (1UL << 52) && h.h4 < (1UL << 52)).IsTrue();

    private static fe25519 RandomLimbs(Random rng)
        => new((ulong)rng.NextInt64() & Limb53, (ulong)rng.NextInt64() & Limb53, (ulong)rng.NextInt64() & Limb53, (ulong)rng.NextInt64() & Limb53, (ulong)rng.NextInt64() & Limb53);

    private static BigInteger Value(in fe25519 f)
        => f.h0 + ((BigInteger)f.h1 << 51) + ((BigInteger)f.h2 << 102) + ((BigInteger)f.h3 << 153) + ((BigInteger)f.h4 << 204);

    private static BigInteger Mod(BigInteger v)
    {
        var r = v % P;
        return r.Sign < 0 ? r + P : r;
    }

    private static byte[] ToBytes(BigInteger v)
    {
        var bytes = new byte[32];
        v.TryWriteBytes(bytes, out _, isUnsigned: true, isBigEndian: false).IsTrue();
        return bytes;
    }

    private static BigInteger FromBytes(ReadOnlySpan<byte> littleEndian) => new(littleEndian, isUnsigned: true, isBigEndian: false);

    private static BigInteger RandomBelow(Random rng, BigInteger bound)
    {
        var bytes = new byte[(int)(bound.GetBitLength() / 8) + 9];
        rng.NextBytes(bytes);
        return new BigInteger(bytes, isUnsigned: true) % bound;
    }
}
