// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Curve25519Benchmark
{
    private byte[] seed;
    private byte[] seed2;
    private byte[] publicKey;
    private byte[] publicKey2;
    private byte[] secretKey;

    public Curve25519Benchmark()
    {
        var random = new Xoshiro256StarStar(12);
        this.seed = new byte[CryptoSignHelper.SeedSizeInBytes];
        this.seed2 = new byte[CryptoSignHelper.SeedSizeInBytes];
        random.NextBytes(this.seed);

        this.secretKey = new byte[CryptoSignHelper.SecretKeySizeInBytes];
        this.publicKey = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        this.publicKey2 = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        CryptoSignHelper.CreateKey(this.seed, this.secretKey, this.publicKey);
    }

    [Benchmark]
    public byte[] CreateKey()
    {
        var secretKey = new byte[CryptoSignHelper.SecretKeySizeInBytes];
        var publicKey = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        CryptoSignHelper.CreateKey(secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] CreateKeyFromSeed()
    {
        var secretKey = new byte[CryptoSignHelper.SecretKeySizeInBytes];
        var publicKey = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        CryptoSignHelper.CreateKey(this.seed, secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] SecretKeyToSeed()
    {
        CryptoSignHelper.SecretKeyToSeed(this.secretKey, this.seed2);
        return this.seed2;
    }

    [Benchmark]
    public byte[] SecretKeyToSeed2()
    {
        CryptoSignHelper.SecretKeyToSeed2(this.secretKey, this.seed2);
        return this.seed2;
    }

    [Benchmark]
    public byte[] SecretKeyToPublicKey()
    {
        CryptoSignHelper.SecretKeyToPublicKey(this.secretKey, this.publicKey2);
        return this.publicKey2;
    }
}
