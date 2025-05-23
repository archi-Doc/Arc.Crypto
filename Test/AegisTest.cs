﻿// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Tinyhand;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access
#pragma warning disable SA1512 // Single-line comments should not be followed by blank line
#pragma warning disable SA1601 // Partial elements should be documented

namespace Test;

[TinyhandObject]
public partial class AegisVector
{
    public AegisVector()
    {
    }

    [Key("result")]
    public bool Result { get; set; }

    [Key("key")]
    public string Key { get; set; } = string.Empty;

    [Key("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [Key("ad")]
    public string Additional { get; set; } = string.Empty;

    [Key("msg")]
    public string Message { get; set; } = string.Empty;

    [Key("ct")]
    public string Cipher { get; set; } = string.Empty;

    [Key("tag128")]
    public string Tag128 { get; set; } = string.Empty;

    [Key("tag256")]
    public string Tag256 { get; set; } = string.Empty;

    public void Test128()
    {
        var key = Hex.FromStringToByteArray(this.Key);
        key.Length.Is(Aegis128L.KeySize);
        var nonce = Hex.FromStringToByteArray(this.Nonce);
        nonce.Length.Is(Aegis128L.NonceSize);
        var message = Hex.FromStringToByteArray(this.Message);
        var cipher = Hex.FromStringToByteArray(this.Cipher);
        var additional = Hex.FromStringToByteArray(this.Additional);
        var tag128 = Hex.FromStringToByteArray(this.Tag128);
        tag128.Length.Is(Aegis128L.MinTagSize);
        var tag256 = Hex.FromStringToByteArray(this.Tag256);
        tag256.Length.Is(Aegis128L.MaxTagSize);

        if (this.Result)
        {
            var c = new byte[message.Length + Aegis128L.MaxTagSize];
            Aegis128L.Encrypt(c.AsSpan(0, message.Length + Aegis128L.MinTagSize), message, nonce, key, additional, Aegis128L.MinTagSize);
            c.AsSpan(0, message.Length).SequenceEqual(cipher).IsTrue();
            c.AsSpan(message.Length, Aegis128L.MinTagSize).SequenceEqual(tag128).IsTrue();

            var d = new byte[message.Length];
            Aegis128L.TryDecrypt(d, c.AsSpan(0, message.Length + Aegis128L.MinTagSize), nonce, key, additional, Aegis128L.MinTagSize).IsTrue();
            d.SequenceEqual(message).IsTrue();

            Aegis128L.Encrypt(c.AsSpan(0, message.Length + Aegis128L.MaxTagSize), message, nonce, key, additional, Aegis128L.MaxTagSize);
            c.AsSpan(0, message.Length).SequenceEqual(cipher).IsTrue();
            c.AsSpan(message.Length, Aegis128L.MaxTagSize).SequenceEqual(tag256).IsTrue();

            Aegis128L.TryDecrypt(d, c.AsSpan(0, message.Length + Aegis128L.MaxTagSize), nonce, key, additional, Aegis128L.MaxTagSize).IsTrue();
            d.SequenceEqual(message).IsTrue();
        }
        else
        {
            var c = new byte[cipher.Length + Aegis128L.MaxTagSize];
            var d = new byte[cipher.Length];
            cipher.AsSpan().CopyTo(c);
            tag128.AsSpan().CopyTo(c.AsSpan(cipher.Length));
            Aegis128L.TryDecrypt(d, c.AsSpan(0, cipher.Length + Aegis128L.MinTagSize), nonce, key, additional, Aegis128L.MinTagSize).IsFalse();

            cipher.AsSpan().CopyTo(c);
            tag256.AsSpan().CopyTo(c.AsSpan(cipher.Length));
            Aegis128L.TryDecrypt(d, c.AsSpan(0, cipher.Length + Aegis128L.MaxTagSize), nonce, key, additional, Aegis128L.MaxTagSize).IsFalse();
        }
    }

    public void Test256()
    {
        var key = Hex.FromStringToByteArray(this.Key);
        key.Length.Is(Aegis256.KeySize);
        var nonce = Hex.FromStringToByteArray(this.Nonce);
        nonce.Length.Is(Aegis256.NonceSize);
        var message = Hex.FromStringToByteArray(this.Message);
        var cipher = Hex.FromStringToByteArray(this.Cipher);
        var additional = Hex.FromStringToByteArray(this.Additional);
        var tag128 = Hex.FromStringToByteArray(this.Tag128);
        tag128.Length.Is(Aegis256.MinTagSize);
        var tag256 = Hex.FromStringToByteArray(this.Tag256);
        tag256.Length.Is(Aegis256.MaxTagSize);

        if (this.Result)
        {
            var c = new byte[message.Length + Aegis256.MaxTagSize];
            Aegis256.Encrypt(c.AsSpan(0, message.Length + Aegis256.MinTagSize), message, nonce, key, additional, Aegis256.MinTagSize);
            c.AsSpan(0, message.Length).SequenceEqual(cipher).IsTrue();
            c.AsSpan(message.Length, Aegis256.MinTagSize).SequenceEqual(tag128).IsTrue();

            var d = new byte[message.Length];
            Aegis256.TryDecrypt(d, c.AsSpan(0, message.Length + Aegis256.MinTagSize), nonce, key, additional, Aegis256.MinTagSize).IsTrue();
            d.SequenceEqual(message).IsTrue();

            Aegis256.Encrypt(c.AsSpan(0, message.Length + Aegis256.MaxTagSize), message, nonce, key, additional, Aegis256.MaxTagSize);
            c.AsSpan(0, message.Length).SequenceEqual(cipher).IsTrue();
            c.AsSpan(message.Length, Aegis256.MaxTagSize).SequenceEqual(tag256).IsTrue();

            Aegis256.TryDecrypt(d, c.AsSpan(0, message.Length + Aegis256.MaxTagSize), nonce, key, additional, Aegis256.MaxTagSize).IsTrue();
            d.SequenceEqual(message).IsTrue();
        }
        else
        {
            var c = new byte[cipher.Length + Aegis256.MaxTagSize];
            var d = new byte[cipher.Length];
            cipher.AsSpan().CopyTo(c);
            tag128.AsSpan().CopyTo(c.AsSpan(cipher.Length));
            Aegis256.TryDecrypt(d, c.AsSpan(0, cipher.Length + Aegis256.MinTagSize), nonce, key, additional, Aegis256.MinTagSize).IsFalse();

            cipher.AsSpan().CopyTo(c);
            tag256.AsSpan().CopyTo(c.AsSpan(cipher.Length));
            Aegis256.TryDecrypt(d, c.AsSpan(0, cipher.Length + Aegis256.MaxTagSize), nonce, key, additional, Aegis256.MaxTagSize).IsFalse();
        }
    }
}

public class AegisTest
{
    [Fact]
    public void Test_MultiThread()
    {
        const int Length = 100;

        Parallel.For(0, 10, x =>
        {
            var random = new Xoroshiro128StarStar(12);
            Span<byte> key256 = new byte[Aegis256.KeySize];
            random.NextBytes(key256);
            Span<byte> nonce256 = new byte[Aegis256.NonceSize];
            random.NextBytes(nonce256);
            Span<byte> key128 = new byte[Aegis128L.KeySize];
            random.NextBytes(key128);
            Span<byte> nonce128 = new byte[Aegis128L.NonceSize];
            random.NextBytes(nonce128);
            Span<byte> message = new byte[Length];
            random.NextBytes(message);
            Span<byte> cipher = new byte[Length + Aegis256.MinTagSize];
            Span<byte> decrypted = new byte[Length];

            for (var i = 0; i < 100; i++)
            {
                Aegis256.Encrypt(cipher, message, nonce256, key256);
                Aegis256.TryDecrypt(decrypted, cipher, nonce256, key256).IsTrue();
                decrypted.SequenceEqual(message).IsTrue();

                Aegis128L.Encrypt(cipher, message, nonce128, key128);
                Aegis128L.TryDecrypt(decrypted, cipher, nonce128, key128).IsTrue();
                decrypted.SequenceEqual(message).IsTrue();
            }
        });
    }

    [Fact]
    public void Test_NoTag()
    {
        const int Length = 100;

        var random = new Xoroshiro128StarStar(12);
        Span<byte> key256 = stackalloc byte[Aegis256.KeySize];
        Span<byte> nonce256 = stackalloc byte[Aegis256.NonceSize];
        Span<byte> key128 = stackalloc byte[Aegis128L.KeySize];
        Span<byte> nonce128 = stackalloc byte[Aegis128L.NonceSize];
        Span<byte> message = stackalloc byte[Length];
        Span<byte> cipher = stackalloc byte[Length];
        Span<byte> decrypted = stackalloc byte[Length];
        random.NextBytes(key256);
        random.NextBytes(nonce256);
        random.NextBytes(message);

        for (var i = 0; i < Length; i += 13)
        {
            Aegis256.Encrypt(cipher[..i], message[..i], nonce256, key256, default, 0);
            Aegis256.TryDecrypt(decrypted[..i], cipher[..i], nonce256, key256, default, 0);
            decrypted[..i].SequenceEqual(message[..i]).IsTrue();

            // decrypted[..i].Clear();
            // Aegis256.Encrypt(decrypted[..i], cipher[..i], nonce256, key256, default, 0);
            // decrypted[..i].SequenceEqual(message[..i]).IsTrue();

            Aegis128L.Encrypt(cipher[..i], message[..i], nonce128, key128, default, 0);
            Aegis128L.TryDecrypt(decrypted[..i], cipher[..i], nonce128, key128, default, 0);
            decrypted[..i].SequenceEqual(message[..i]).IsTrue();
        }
    }

    [Fact]
    public void TestVectors_128()
    {
        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        Arc.BaseHelper.TryLoadResource(assembly, "Resources.Aegis128Vectors.tinyhand", out var data);
        var vectors = TinyhandSerializer.DeserializeFromUtf8<AegisVector[]>(data!)!;

        foreach (var x in vectors)
        {
            x.Test128();
        }
    }

    [Fact]
    public void TestVectors_256()
    {
        var assembly = System.Reflection.Assembly.GetExecutingAssembly();
        Arc.BaseHelper.TryLoadResource(assembly, "Resources.Aegis256Vectors.tinyhand", out var data);
        var vectors = TinyhandSerializer.DeserializeFromUtf8<AegisVector[]>(data!)!;

        foreach (var x in vectors)
        {
            x.Test256();
        }
    }

    [Fact]
    public void Test256()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> key = stackalloc byte[Aegis256.KeySize];
        Span<byte> nonce = stackalloc byte[Aegis256.NonceSize];

        for (var j = 0; j < 1000; j += 13)
        {
            var message = new byte[j].AsSpan();
            var message2 = new byte[j].AsSpan();
            random.NextBytes(message);
            var cipher = new byte[message.Length + Aegis256.MaxTagSize].AsSpan();
            var cipher2 = new byte[message.Length + Aegis256.MaxTagSize].AsSpan();

            Aegis256.Encrypt(cipher, message, nonce, key, default, 32);
            Aegis256.TryDecrypt(message2, cipher, nonce, key, default, 32).IsTrue();
            message.SequenceEqual(message2).IsTrue();

            Aegis256Helper.Encrypt(message, nonce, key, cipher2, out _);
            cipher.SequenceEqual(cipher2).IsTrue();

            // Same span
            cipher2.Clear();
            message.CopyTo(cipher2);
            Aegis256.Encrypt(cipher2, cipher2[..^32], nonce, key, default, 32);
            cipher.SequenceEqual(cipher2).IsTrue();
            Aegis256.TryDecrypt(cipher2[..^32], cipher2, nonce, key, default, 32).IsTrue();
            message.SequenceEqual(cipher2[..^32]).IsTrue();
        }
    }

    [Fact]
    public void Test128()
    {
        var random = new Xoroshiro128StarStar(12);
        Span<byte> key = stackalloc byte[Aegis128L.KeySize];
        Span<byte> nonce = stackalloc byte[Aegis128L.NonceSize];

        for (var j = 0; j < 1000; j += 13)
        {
            var message = new byte[j];
            var message2 = new byte[j];
            random.NextBytes(message);
            var cipher = new byte[message.Length + Aegis128L.MaxTagSize];
            var cipher2 = new byte[message.Length + Aegis128L.MaxTagSize];

            Aegis128L.Encrypt(cipher, message, nonce, key, default, 32);
            Aegis128L.TryDecrypt(message2, cipher, nonce, key, default, 32);
            message.SequenceEqual(message2).IsTrue();
        }
    }

    [Fact]
    public void DoubleEncryption32()
    {
        const int length = 32;
        var random = new Xoroshiro128StarStar(11);
        Span<byte> key = stackalloc byte[Aegis256.KeySize];
        Span<byte> nonce = stackalloc byte[Aegis256.NonceSize];
        var message = new byte[length];
        var message2 = new byte[length];
        var message3 = new byte[length];
        var cipher = new byte[length];

        for (var j = 0; j < 10; j++)
        {
            random.NextBytes(key);
            random.NextBytes(nonce);
            random.NextBytes(message);

            Aegis256.Encrypt(cipher, message, nonce, key, default, 0);
            Aegis256.TryDecrypt(message2, cipher, nonce, key, default, 0).IsTrue();
            message.SequenceEqual(message2).IsTrue();
            Aegis256.Encrypt(message3, cipher, nonce, key, default, 0);
            message.SequenceEqual(message3).IsTrue();
        }
    }
}
