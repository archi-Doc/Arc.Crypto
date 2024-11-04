// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class DsaTest
{
    [Fact]
    public void Test1()
    {
        NSec.Cryptography.Ed25519 nsec = new(); // NSec
        var algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;

        var random = new Xoroshiro128StarStar(12);
        Span<byte> sign = stackalloc byte[Ed25519Helper.SignatureSizeInBytes];
        Span<byte> pri2 = stackalloc byte[64];
        Span<byte> pub2 = stackalloc byte[32];
        for (var i = 0; i < 32; i++)
        {
            var seed = new byte[Ed25519Helper.PrivateKeySeedSizeInBytes];
            random.NextBytes(seed);

            Rebex.Security.Cryptography.Ed25519 rebex = new(); // Rebex
            rebex.FromSeed(seed);

            Ed25519Helper.KeyPairFromSeed(seed, out var pub, out var pri);
            rebex.GetPublicKey().SequenceEqual(pub).IsTrue();
            rebex.GetPrivateKey().SequenceEqual(pri).IsTrue();

            for (var j = 0; j < 1000; j += 10)
            {
                var message = new byte[i + j];
                random.NextBytes(message);

                var signRebex = rebex.SignMessage(message);
                Ed25519Helper.Sign(message, pri, sign);
                sign.SequenceEqual(signRebex).IsTrue();

                Ed25519Helper.Verify(message, pub, sign).IsTrue();
            }

            /*NSec.Cryptography.KeyCreationParameters param;
            param.ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport;
            var key = NSec.Cryptography.Key.Create(algorithm, param);
            key.TryExport(NSec.Cryptography.KeyBlobFormat.RawPublicKey, pub2, out _).IsTrue();
            key.TryExport(NSec.Cryptography.KeyBlobFormat.RawPrivateKey, pri2, out _).IsTrue();

            for (var j = 0; j < 1000; j += 10)
            {
                var message = new byte[i + j];
                random.NextBytes(message);

                var signNsec = algorithm.Sign(key, message);
                Ed25519Helper.Sign(message, pri2, sign);
                sign.SequenceEqual(signNsec).IsTrue();

                Ed25519Helper.Verify(message, pub2, sign).IsTrue();
            }*/
        }
    }
}
