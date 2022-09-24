// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Arc.Crypto.EC;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class ECKeyCompressionTest
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
}
