// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using BenchmarkDotNet.Attributes;

namespace Benchmark;

[Config(typeof(BenchmarkConfig))]
public class Curve25519Benchmark
{
    private byte[] seed;
    private byte[] seed2;
    private byte[] nonce24;
    private byte[] cryptoSignPublicKey;
    private byte[] cryptoSignPublicKey2;
    private byte[] cryptoSignSecretKey;
    private byte[] cryptoBoxPublicKey;
    private byte[] cryptoBoxSecretKey;
    private byte[] cryptoBoxPublicKey2;
    private byte[] cryptoBoxSecretKey2;
    private byte[] message;
    private byte[] message2;
    private byte[] cipher;

    public Curve25519Benchmark()
    {
        var random = new Xoshiro256StarStar(12);
        this.seed = new byte[CryptoSignHelper.SeedSizeInBytes];
        this.seed2 = new byte[CryptoSignHelper.SeedSizeInBytes];
        random.NextBytes(this.seed);
        random.NextBytes(this.seed2);
        this.nonce24 = new byte[CryptoBoxHelper.NonceSizeInBytes];
        random.NextBytes(this.nonce24);

        this.cryptoSignSecretKey = new byte[CryptoSignHelper.SecretKeySizeInBytes];
        this.cryptoSignPublicKey = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        this.cryptoSignPublicKey2 = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        CryptoSignHelper.CreateKey(this.seed, this.cryptoSignSecretKey, this.cryptoSignPublicKey);

        this.cryptoBoxPublicKey = new byte[CryptoBoxHelper.SecretKeySizeInBytes];
        this.cryptoBoxSecretKey = new byte[CryptoBoxHelper.PublicKeySizeInBytes];
        CryptoBoxHelper.CreateKey(this.seed, this.cryptoBoxSecretKey, this.cryptoBoxPublicKey);
        this.cryptoBoxPublicKey2 = new byte[CryptoBoxHelper.SecretKeySizeInBytes];
        this.cryptoBoxSecretKey2 = new byte[CryptoBoxHelper.PublicKeySizeInBytes];
        CryptoBoxHelper.CreateKey(this.seed2, this.cryptoBoxSecretKey2, this.cryptoBoxPublicKey2);

        this.message = new byte[32];
        this.message2 = new byte[32];
        for (var i = 0; i < this.message.Length; i++)
        {
            this.message[i] = (byte)(i & 255);
        }

        this.cipher = new byte[this.message.Length + CryptoBoxHelper.MacSizeInBytes];
    }

    [Benchmark]
    public byte[] CryptoSign_CreateKey()
    {
        var secretKey = new byte[CryptoSignHelper.SecretKeySizeInBytes];
        var publicKey = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        CryptoSignHelper.CreateKey(secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] CryptoSign_CreateKeyFromSeed()
    {
        var secretKey = new byte[CryptoSignHelper.SecretKeySizeInBytes];
        var publicKey = new byte[CryptoSignHelper.PublicKeySizeInBytes];
        CryptoSignHelper.CreateKey(this.seed, secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] CryptoSign_SecretKeyToSeed()
    {
        CryptoSignHelper.SecretKeyToSeed(this.cryptoSignSecretKey, this.seed2);
        return this.seed2;
    }

    [Benchmark]
    public byte[] CryptoSign_SecretKeyToSeed2()
    {
        CryptoSignHelper.SecretKeyToSeed2(this.cryptoSignSecretKey, this.seed2);
        return this.seed2;
    }

    [Benchmark]
    public byte[] CryptoSign_SecretKeyToPublicKey()
    {
        CryptoSignHelper.SecretKeyToPublicKey(this.cryptoSignSecretKey, this.cryptoSignPublicKey2);
        return this.cryptoSignPublicKey2;
    }

    [Benchmark]
    public byte[] CryptoBox_CreateKey()
    {
        var secretKey = new byte[CryptoBoxHelper.SecretKeySizeInBytes];
        var publicKey = new byte[CryptoBoxHelper.PublicKeySizeInBytes];
        CryptoBoxHelper.CreateKey(secretKey, publicKey);
        return secretKey;
    }

    [Benchmark]
    public byte[] CryptoBox_EncryptoDecrypto()
    {
        CryptoBoxHelper.Encrypt(this.message, this.nonce24, this.cryptoBoxSecretKey, this.cryptoBoxPublicKey2, this.cipher);
        CryptoBoxHelper.Decrypt(this.cipher, this.nonce24, this.cryptoBoxSecretKey2, this.cryptoBoxPublicKey, this.message2);
        return this.message2;
    }
}
