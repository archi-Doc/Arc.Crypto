// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access
#pragma warning disable SA1512 // Single-line comments should not be followed by blank line
#pragma warning disable SA1601 // Partial elements should be documented
#pragma warning disable SA1649 // File name should match first type name

namespace Test;

/// <summary>
/// A single AEGIS test vector loaded from the embedded <c>*Vectors.tinyhand</c> resources.
/// </summary>
public class AegisVector
{
    public bool Result { get; set; }

    public string Key { get; set; } = string.Empty;

    public string Nonce { get; set; } = string.Empty;

    public string Additional { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;

    public string Cipher { get; set; } = string.Empty;

    public string Tag128 { get; set; } = string.Empty;

    public string Tag256 { get; set; } = string.Empty;

    /// <summary>
    /// Loads the vectors from an embedded resource whose name ends with <paramref name="resourceSuffix"/>.
    /// </summary>
    /// <param name="resourceSuffix">The trailing part of the embedded resource name.</param>
    /// <returns>The parsed test vectors.</returns>
    /// <remarks>
    /// The resource files use the tinyhand text format, but the schema here is a flat list of
    /// hex strings, so it is parsed directly rather than pulling in a serializer dependency.
    /// </remarks>
    public static AegisVector[] Load(string resourceSuffix)
    {
        var assembly = typeof(AegisVector).Assembly;
        string? name = null;
        foreach (var x in assembly.GetManifestResourceNames())
        {
            if (x.EndsWith(resourceSuffix, StringComparison.Ordinal))
            {
                name = x;
                break;
            }
        }

        Assert.NotNull(name);
        using var stream = assembly.GetManifestResourceStream(name!);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        var vectors = Parse(reader.ReadToEnd());
        Assert.NotEmpty(vectors);
        return vectors;
    }

    internal static AegisVector[] Parse(string text)
    {
        var list = new List<AegisVector>();
        foreach (var block in text.Split('+', StringSplitOptions.RemoveEmptyEntries))
        {
            var result = Regex.Match(block, @"result\s*=\s*(true|false)");
            if (!result.Success)
            {
                continue;
            }

            list.Add(new AegisVector
            {
                Result = result.Groups[1].Value == "true",
                Key = Field(block, "key"),
                Nonce = Field(block, "nonce"),
                Additional = Field(block, "ad"),
                Message = Field(block, "msg"),
                Cipher = Field(block, "ct"),
                Tag128 = Field(block, "tag128"),
                Tag256 = Field(block, "tag256"),
            });
        }

        return list.ToArray();

        static string Field(string block, string key)
        {
            var m = Regex.Match(block, @"(?:^|\W)" + key + @"\s*=\s*""([0-9a-fA-F]*)""");
            return m.Success ? m.Groups[1].Value : string.Empty;
        }
    }

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

            Aegis128L.Encrypt(cipher[..i], message[..i], nonce128, key128, default, 0);
            Aegis128L.TryDecrypt(decrypted[..i], cipher[..i], nonce128, key128, default, 0);
            decrypted[..i].SequenceEqual(message[..i]).IsTrue();
        }
    }

    [Fact]
    public void TestVectors_128()
    {
        foreach (var x in AegisVector.Load("Aegis128Vectors.tinyhand"))
        {
            x.Test128();
        }
    }

    [Fact]
    public void TestVectors_256()
    {
        foreach (var x in AegisVector.Load("Aegis256Vectors.tinyhand"))
        {
            x.Test256();
        }
    }

    /// <summary>
    /// Cross-checks the managed x86/ARM path against the portable software path over a wide
    /// range of plaintext, associated-data and tag lengths, so that a regression in one backend
    /// cannot pass unnoticed on a machine where only the other one runs.
    /// </summary>
    [Fact]
    public void Backends_Agree()
    {
        var random = new Xoroshiro128StarStar(31);
        var key128 = new byte[Aegis128L.KeySize];
        var nonce128 = new byte[Aegis128L.NonceSize];
        var key256 = new byte[Aegis256.KeySize];
        var nonce256 = new byte[Aegis256.NonceSize];
        random.NextBytes(key128);
        random.NextBytes(nonce128);
        random.NextBytes(key256);
        random.NextBytes(nonce256);

        foreach (var length in new[] { 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000 })
        {
            foreach (var adLength in new[] { 0, 1, 15, 16, 17, 31, 32, 33, 100 })
            {
                foreach (var tagSize in new[] { 0, Aegis128L.MinTagSize, Aegis128L.MaxTagSize })
                {
                    var message = new byte[length];
                    var additional = new byte[adLength];
                    random.NextBytes(message);
                    random.NextBytes(additional);

                    var actual = new byte[length + tagSize];
                    var expected = new byte[length + tagSize];
                    var decrypted = new byte[length];

                    Aegis128L.Encrypt(actual, message, nonce128, key128, additional, tagSize);
                    Aegis128LSoft.Encrypt(expected, message, nonce128, key128, additional, tagSize);
                    actual.SequenceEqual(expected).IsTrue();
                    Aegis128L.TryDecrypt(decrypted, actual, nonce128, key128, additional, tagSize).IsTrue();
                    decrypted.SequenceEqual(message).IsTrue();

                    Aegis256.Encrypt(actual, message, nonce256, key256, additional, tagSize);
                    Aegis256Soft.Encrypt(expected, message, nonce256, key256, additional, tagSize);
                    actual.SequenceEqual(expected).IsTrue();
                    Aegis256.TryDecrypt(decrypted, actual, nonce256, key256, additional, tagSize).IsTrue();
                    decrypted.SequenceEqual(message).IsTrue();

                    if (tagSize > 0 && actual.Length > 0)
                    {
                        // A single flipped bit anywhere in the ciphertext or tag must be rejected.
                        actual[actual.Length - 1] ^= 0x80;
                        Aegis256.TryDecrypt(decrypted, actual, nonce256, key256, additional, tagSize).IsFalse();
                    }
                }
            }
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
