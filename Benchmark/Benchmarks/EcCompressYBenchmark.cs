// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto.EC;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

#pragma warning disable SA1310 // Field names should not contain underscore

/// <summary>
/// Measures one point-compression round trip on the two 256-bit short Weierstrass curves:
/// <see cref="ECCurveBase.CompressY(ReadOnlySpan{byte})"/> followed by
/// <see cref="ECCurveBase.TryDecompressY(ReadOnlySpan{byte}, uint)"/>.
/// The two calls form a single set, so each benchmark method performs exactly one of each.
/// </summary>
/// <remarks>
/// The key pairs are generated in the constructor so that only the compression round trip is timed.
/// <see cref="ECCurveBase.CompressY(ReadOnlySpan{byte})"/> just reads the low bit of the last byte;
/// essentially all of the measured time is the modular square root inside
/// <see cref="ECCurveBase.TryDecompressY(ReadOnlySpan{byte}, uint)"/>, which also allocates the
/// returned y coordinate (visible in the Allocated column).
/// </remarks>
[Config(typeof(BenchmarkConfig))]
public class EcCompressYBenchmark
{
    private readonly byte[] r1X;
    private readonly byte[] r1Y;
    private readonly byte[] k1X;
    private readonly byte[] k1Y;

    public EcCompressYBenchmark()
    {
        (this.r1X, this.r1Y) = CreatePoint("secp256r1");
        (this.k1X, this.k1Y) = CreatePoint("secp256k1");

        // TryDecompressY returns null on a curve/length mismatch, and that failure path is far
        // cheaper than a real decompression. Verify the round trip up front so the benchmark
        // cannot silently report the timing of a failure instead of the timing of the work.
        Verify(this.P256R1_CompressDecompress(), this.r1Y, "secp256r1");
        Verify(this.P256K1_CompressDecompress(), this.k1Y, "secp256k1");

        static (byte[] X, byte[] Y) CreatePoint(string friendlyName)
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName(friendlyName));
            var p = ecdh.ExportParameters(false);
            return (p.Q.X!, p.Q.Y!);
        }

        static void Verify(byte[]? actual, byte[] expected, string curveName)
        {
            if (actual is null || !actual.SequenceEqual(expected))
            {
                throw new InvalidOperationException($"{curveName}: CompressY/TryDecompressY did not round-trip.");
            }
        }
    }

    [Benchmark(Baseline = true, Description = "secp256r1 CompressY + TryDecompressY")]
    public byte[]? P256R1_CompressDecompress()
    {
        var yt = P256R1Curve.Instance.CompressY(this.r1Y);
        return P256R1Curve.Instance.TryDecompressY(this.r1X, yt);
    }

    [Benchmark(Description = "secp256k1 CompressY + TryDecompressY")]
    public byte[]? P256K1_CompressDecompress()
    {
        var yt = P256K1Curve.Instance.CompressY(this.k1Y);
        return P256K1Curve.Instance.TryDecompressY(this.k1X, yt);
    }
}
