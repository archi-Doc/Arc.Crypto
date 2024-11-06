// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Ed25519Benchmark
{
    private byte[] seed;
    private byte[] seed2;
    private byte[] publicKey;
    private byte[] publicKey2;
    private byte[] secretKey;

    public Ed25519Benchmark()
    {
        var random = new Xoshiro256StarStar(12);
        this.seed = new byte[Ed25519Helper.SeedSizeInBytes];
        this.seed2 = new byte[Ed25519Helper.SeedSizeInBytes];
        random.NextBytes(this.seed);

        this.secretKey = new byte[Ed25519Helper.SecretKeySizeInBytes];
        this.publicKey = new byte[Ed25519Helper.PublicKeySizeInBytes];
        this.publicKey2 = new byte[Ed25519Helper.PublicKeySizeInBytes];
        Ed25519Helper.CreateKey(this.seed, this.secretKey, this.publicKey);
    }

    [Benchmark]
    public byte[] CreateKey()
    {
        var secretKey = new byte[Ed25519Helper.SecretKeySizeInBytes];
        var publicKey = new byte[Ed25519Helper.PublicKeySizeInBytes];
        Ed25519Helper.CreateKey(secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] CreateKeyFromSeed()
    {
        var secretKey = new byte[Ed25519Helper.SecretKeySizeInBytes];
        var publicKey = new byte[Ed25519Helper.PublicKeySizeInBytes];
        Ed25519Helper.CreateKey(this.seed, secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] SecretKeyToSeed()
    {
        Ed25519Helper.SecretKeyToSeed(this.secretKey, this.seed2);
        return this.seed2;
    }

    [Benchmark]
    public byte[] SecretKeyToPublicKey()
    {
        Ed25519Helper.SecretKeyToPublicKey(this.secretKey, this.publicKey2);
        return this.publicKey2;
    }
}
