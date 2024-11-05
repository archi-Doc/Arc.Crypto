// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using BenchmarkDotNet.Attributes;
using Rebex.Security.Cryptography;

namespace Benchmark;

#pragma warning disable SA1310 // Field names should not contain underscore
#pragma warning disable SA1405 // Debug.Assert should provide message text

[Config(typeof(BenchmarkConfig))]
public class DsaBenchmark
{
    private readonly ECCurve curve;
    private readonly ECDsa ecdsa;
    private readonly Ed25519 ed25519;
    // private readonly NSec.Cryptography.SignatureAlgorithm algorithm;
    // private readonly NSec.Cryptography.Key key;
    private readonly byte[] message;
    private readonly byte[] hash;
    private readonly byte[] signSecp256r1;
    private readonly byte[] signEd25519;
    // private readonly byte[] signEd25519B;
    private readonly byte[] pri2;
    private readonly byte[] pub2;
    private readonly byte[] signature;

    public DsaBenchmark()
    {
        this.curve = ECCurve.CreateFromFriendlyName("secp256r1");
        this.message = new byte[] { 0, 1, 2, 3, };

        ECParameters p = default;
        p.Curve = this.curve;
        p.D = Sha3Helper.Get256_ByteArray([]);
        this.ecdsa = ECDsa.Create(p);
        this.hash = Sha2Helper.Get256_ByteArray(this.message);
        this.signSecp256r1 = this.ecdsa.SignHash(this.hash);
        var verify = this.ecdsa.VerifyHash(this.hash, this.signSecp256r1);

        this.ed25519 = new Ed25519();
        this.ed25519.FromSeed(Sha3Helper.Get256_ByteArray([]));
        this.signEd25519 = this.ed25519.SignMessage(this.message);
        verify = this.ed25519.VerifyMessage(this.message, this.signEd25519);

        var pri = this.ed25519.GetPrivateKey();
        var pub = this.ed25519.GetPublicKey();
        Ed25519Helper.KeyPairFromSeed(Sha3Helper.Get256_ByteArray([]), out this.pub2, out this.pri2);
        Debug.Assert(pri.SequenceEqual(this.pri2));
        Debug.Assert(pub.SequenceEqual(this.pub2));
        this.signature = new byte[Ed25519Helper.SignatureSizeInBytes];
        Ed25519Helper.Sign(this.message, this.pri2, this.signature);
        Debug.Assert(this.signature.SequenceEqual(this.signEd25519));
        verify = Ed25519Helper.Verify(this.message, this.pub2, this.signature);

        /*this.algorithm = NSec.Cryptography.SignatureAlgorithm.Ed25519;
        this.key = NSec.Cryptography.Key.Create(this.algorithm);
        this.signEd25519B = this.algorithm.Sign(this.key, this.message);
        verify = this.algorithm.Verify(this.key.PublicKey, this.message, this.signEd25519B);*/
    }

    [Params(10)]
    public int Length { get; set; }

    [GlobalSetup]
    public void Setup()
    {
    }

    [GlobalCleanup]
    public void Cleanup()
    {
    }

    [Benchmark]
    public byte[] SignSecp256r1()
    {
        return this.ecdsa.SignHash(this.hash);
    }

    [Benchmark]
    public byte[] SignEd25519_NaCl()
    {
        return this.ed25519.SignMessage(this.message);
    }

    /*[Benchmark]
    public byte[] SignEd25519B_NSec()
    {
        return this.algorithm.Sign(this.key, this.message);
    }*/

    [Benchmark]
    public byte[] SignEd25519()
    {
        Ed25519Helper.Sign(this.message, this.pri2, this.signature);
        return this.signature;
    }

    [Benchmark]
    public bool VerifySecp256r1()
    {
        return this.ecdsa.VerifyHash(this.hash, this.signSecp256r1);
    }

    [Benchmark]
    public bool VerifyEd25519_NaCl()
    {
        return this.ed25519.VerifyMessage(this.message, this.signEd25519);
    }

    /*[Benchmark]
    public bool VerifyEd25519_NSec()
    {
        var b = this.algorithm.Verify(this.key.PublicKey, this.message, this.signEd25519B);
        return b;
    }*/

    [Benchmark]
    public bool VerifyEd25519()
    {
        return Ed25519Helper.Verify(this.message, this.pub2, this.signature);
    }
}
