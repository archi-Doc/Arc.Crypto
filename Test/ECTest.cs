// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Arc.Crypto.EC;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class ECTest
{
    [Fact]
    public void Test1()
    {
        var curve = ECCurve.CreateFromFriendlyName("secp256r1");
        for (var i = 0; i < 100; i++)
        {
            using (var ecdh = ECDiffieHellman.Create(curve))
            {
                var p = ecdh.ExportParameters(false);

                var yt = P256R1Curve.Instance.CompressY(p.Q.Y!);
                var y = P256R1Curve.Instance.TryDecompressY(p.Q.X!, yt);
                y!.SequenceEqual(p.Q.Y!).IsTrue();
            }
        }

        curve = ECCurve.CreateFromFriendlyName("secp256k1");
        for (var i = 0; i < 100; i++)
        {
            using (var ecdh = ECDiffieHellman.Create(curve))
            {
                var p = ecdh.ExportParameters(false);

                var yt = P256K1Curve.Instance.CompressY(p.Q.Y!);
                var y = P256K1Curve.Instance.TryDecompressY(p.Q.X!, yt);
                y!.SequenceEqual(p.Q.Y!).IsTrue();
            }
        }
    }

    [Fact]
    public void SeedTest()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(() => xo.NextUInt64(), x => xo.NextBytes(x));

        P256K1Curve.Instance.IsValidSeed(new byte[1]).IsFalse();

        var seed = new byte[P256K1Curve.Instance.ByteLength];
        P256K1Curve.Instance.IsValidSeed(seed).IsFalse();

        var order = Hex.FromStringToByteArray(P256K1Curve.HexOrder);
        P256K1Curve.Instance.IsValidSeed(order).IsFalse();
        order[order.Length - 1]++;
        P256K1Curve.Instance.IsValidSeed(order).IsFalse();

        for (var i = 0; i < 1; i++)
        {
            rv.NextBytes(seed);

            P256K1Curve.Instance.IsValidSeed(seed);
        }

        P256R1Curve.Instance.IsValidSeed(new byte[1]).IsFalse();

        seed = new byte[P256R1Curve.Instance.ByteLength];
        P256R1Curve.Instance.IsValidSeed(seed).IsFalse();

        order = Hex.FromStringToByteArray(P256R1Curve.HexOrder);
        P256R1Curve.Instance.IsValidSeed(order).IsFalse();
        order[order.Length - 1]++;
        P256R1Curve.Instance.IsValidSeed(order).IsFalse();

        for (var i = 0; i < 1; i++)
        {
            rv.NextBytes(seed);

            P256R1Curve.Instance.IsValidSeed(seed);
        }
    }
}
