// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Arc.Crypto;
using Arc.Threading;
using Tinyhand;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access
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
            var message = new byte[j];
            var message2 = new byte[j];
            random.NextBytes(message);
            var cipher = new byte[message.Length + Aegis256.MaxTagSize];
            var cipher2 = new byte[message.Length + Aegis256.MaxTagSize];

            Aegis256.Encrypt(cipher, message, nonce, key, default, 32);
            Aegis256.TryDecrypt(message2, cipher, nonce, key, default, 32);
            message.SequenceEqual(message2).IsTrue();

            Aegis256Helper.Encrypt(message, nonce, key, cipher2, out _);
            cipher.SequenceEqual(cipher2).IsTrue();
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
}
