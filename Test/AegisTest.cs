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

            // Without a tag, the output is the same ciphertext body.
            var c0 = new byte[message.Length];
            Aegis128L.Encrypt(c0, message, nonce, key, additional, 0);
            c0.SequenceEqual(cipher).IsTrue();
            d.AsSpan().Fill(0xA5);
            Aegis128L.TryDecrypt(d, c0, nonce, key, additional, 0).IsTrue();
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

            // Without a tag, the output is the same ciphertext body.
            var c0 = new byte[message.Length];
            Aegis256.Encrypt(c0, message, nonce, key, additional, 0);
            c0.SequenceEqual(cipher).IsTrue();
            d.AsSpan().Fill(0xA5);
            Aegis256.TryDecrypt(d, c0, nonce, key, additional, 0).IsTrue();
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
    private delegate void EncryptFunc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize);

    private delegate bool DecryptFunc(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData, int tagSize);

    [Fact]
    public void Test_MultiThread()
    {
        const int Length = 100;
        const int Threads = 10;

        // Each thread uses its own seed, so a race on shared state would mix different inputs and corrupt the output.
        // The expected ciphertexts come from a single-threaded run.
        var expected256 = new byte[Threads][];
        var expected128 = new byte[Threads][];
        for (var x = 0; x < Threads; x++)
        {
            var (key256, nonce256, key128, nonce128, message) = CreateInput(x);
            expected256[x] = new byte[Length + Aegis256.MinTagSize];
            Aegis256.Encrypt(expected256[x], message, nonce256, key256);
            expected128[x] = new byte[Length + Aegis128L.MinTagSize];
            Aegis128L.Encrypt(expected128[x], message, nonce128, key128);
        }

        Parallel.For(0, Threads, x =>
        {
            var (key256, nonce256, key128, nonce128, message) = CreateInput(x);
            var cipher = new byte[Length + Aegis256.MinTagSize];
            var decrypted = new byte[Length];

            for (var i = 0; i < 100; i++)
            {
                Aegis256.Encrypt(cipher, message, nonce256, key256);
                cipher.SequenceEqual(expected256[x]).IsTrue();
                Aegis256.TryDecrypt(decrypted, cipher, nonce256, key256).IsTrue();
                decrypted.SequenceEqual(message).IsTrue();

                Aegis128L.Encrypt(cipher, message, nonce128, key128);
                cipher.SequenceEqual(expected128[x]).IsTrue();
                Aegis128L.TryDecrypt(decrypted, cipher, nonce128, key128).IsTrue();
                decrypted.SequenceEqual(message).IsTrue();
            }
        });

        static (byte[] Key256, byte[] Nonce256, byte[] Key128, byte[] Nonce128, byte[] Message) CreateInput(int x)
        {
            var random = new Xoroshiro128StarStar(12 + (ulong)x);
            var key256 = new byte[Aegis256.KeySize];
            random.NextBytes(key256);
            var nonce256 = new byte[Aegis256.NonceSize];
            random.NextBytes(nonce256);
            var key128 = new byte[Aegis128L.KeySize];
            random.NextBytes(key128);
            var nonce128 = new byte[Aegis128L.NonceSize];
            random.NextBytes(nonce128);
            var message = new byte[Length];
            random.NextBytes(message);
            return (key256, nonce256, key128, nonce128, message);
        }
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
        random.NextBytes(key128);
        random.NextBytes(nonce128);
        random.NextBytes(message);

        for (var i = 0; i < Length; i += 13)
        {
            Aegis256.Encrypt(cipher[..i], message[..i], nonce256, key256, default, 0);
            Aegis256.TryDecrypt(decrypted[..i], cipher[..i], nonce256, key256, default, 0).IsTrue();
            decrypted[..i].SequenceEqual(message[..i]).IsTrue();

            Aegis128L.Encrypt(cipher[..i], message[..i], nonce128, key128, default, 0);
            Aegis128L.TryDecrypt(decrypted[..i], cipher[..i], nonce128, key128, default, 0).IsTrue();
            decrypted[..i].SequenceEqual(message[..i]).IsTrue();
        }
    }

    [Fact]
    public void TestVectors_128()
    {
        var vectors = AegisVector.Load("Aegis128Vectors.tinyhand");
        vectors.Length.Is(9); // The resource holds 9 vectors; a parsing change must not drop any.
        foreach (var x in vectors)
        {
            x.Test128();
        }
    }

    [Fact]
    public void TestVectors_256()
    {
        var vectors = AegisVector.Load("Aegis256Vectors.tinyhand");
        vectors.Length.Is(9); // The resource holds 9 vectors; a parsing change must not drop any.
        foreach (var x in vectors)
        {
            x.Test256();
        }
    }

    /// <summary>
    /// Cross-checks both ciphers, on the dispatched and the portable path, against libsodium (32-byte tag)
    /// over multi-block messages and associated data with random keys and nonces.
    /// The tag-0 output must equal the libsodium ciphertext body.
    /// </summary>
    [Fact]
    public void Libsodium_Agrees()
    {
        var random = new Xoroshiro128StarStar(123);
        var key128 = new byte[Aegis128L.KeySize];
        var nonce128 = new byte[Aegis128L.NonceSize];
        var key256 = new byte[Aegis256.KeySize];
        var nonce256 = new byte[Aegis256.NonceSize];

        foreach (var length in new[] { 0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 1000 })
        {
            foreach (var adLength in new[] { 0, 1, 31, 32, 33, 64, 65, 100, 1000 })
            {
                random.NextBytes(key128);
                random.NextBytes(nonce128);
                random.NextBytes(key256);
                random.NextBytes(nonce256);
                var message = new byte[length];
                random.NextBytes(message);
                var additional = new byte[adLength];
                random.NextBytes(additional);
                var expected = new byte[length + Aegis128LHelper.ASizeInBytes];
                var actual = new byte[length + Aegis128L.MaxTagSize];
                var body = new byte[length];
                var decrypted = new byte[length];

                Aegis128LHelper.Encrypt(message, additional, nonce128, key128, expected);
                Check(Aegis128L.Encrypt, Aegis128LSoft.Encrypt, Aegis128L.TryDecrypt, Aegis128LSoft.Decrypt, nonce128, key128);

                Aegis256Helper.Encrypt(message, additional, nonce256, key256, expected);
                Check(Aegis256.Encrypt, Aegis256Soft.Encrypt, Aegis256.TryDecrypt, Aegis256Soft.Decrypt, nonce256, key256);

                void Check(EncryptFunc encrypt, EncryptFunc softEncrypt, DecryptFunc decrypt, DecryptFunc softDecrypt, byte[] nonce, byte[] key)
                {
                    actual.AsSpan().Clear();
                    encrypt(actual, message, nonce, key, additional, 32);
                    actual.SequenceEqual(expected).IsTrue();
                    actual.AsSpan().Clear();
                    softEncrypt(actual, message, nonce, key, additional, 32);
                    actual.SequenceEqual(expected).IsTrue();

                    body.AsSpan().Clear();
                    encrypt(body, message, nonce, key, additional, 0);
                    body.AsSpan().SequenceEqual(expected.AsSpan(0, length)).IsTrue();

                    decrypted.AsSpan().Fill(0xA5);
                    decrypt(decrypted, expected, nonce, key, additional, 32).IsTrue();
                    decrypted.SequenceEqual(message).IsTrue();
                    decrypted.AsSpan().Fill(0xA5);
                    softDecrypt(decrypted, expected, nonce, key, additional, 32).IsTrue();
                    decrypted.SequenceEqual(message).IsTrue();
                }
            }
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
            random.NextBytes(key);
            random.NextBytes(nonce);
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
            random.NextBytes(key);
            random.NextBytes(nonce);
            var message = new byte[j];
            var message2 = new byte[j];
            random.NextBytes(message);
            var cipher = new byte[message.Length + Aegis128L.MaxTagSize];
            var cipher2 = new byte[message.Length + Aegis128L.MaxTagSize];

            Aegis128L.Encrypt(cipher, message, nonce, key, default, 32);
            Aegis128L.TryDecrypt(message2, cipher, nonce, key, default, 32).IsTrue();
            message.SequenceEqual(message2).IsTrue();

            Aegis128LHelper.Encrypt(message, default, nonce, key, cipher2);
            cipher.SequenceEqual(cipher2).IsTrue();
        }
    }

    [Fact]
    public void DoubleEncryption32()
    {
        // Encrypting twice restores the message only up to 32 bytes: the plaintext is absorbed into s0 alone,
        // and the second keystream block does not read s0, so the first two keystream blocks do not depend on the plaintext.
        const int length = 32;
        var random = new Xoroshiro128StarStar(11);
        Span<byte> key = stackalloc byte[Aegis256.KeySize];
        Span<byte> nonce = stackalloc byte[Aegis256.NonceSize];
        var message = new byte[length];
        var message2 = new byte[length];
        var message3 = new byte[length];
        var cipher = new byte[length];
        var reference = new byte[length + Aegis256Helper.ASizeInBytes];

        for (var j = 0; j < 10; j++)
        {
            random.NextBytes(key);
            random.NextBytes(nonce);
            random.NextBytes(message);

            Aegis256.Encrypt(cipher, message, nonce, key, default, 0);
            cipher.SequenceEqual(message).IsFalse();
            Aegis256Helper.Encrypt(message, default, nonce, key, reference);
            cipher.AsSpan().SequenceEqual(reference.AsSpan(0, length)).IsTrue();
            Aegis256.TryDecrypt(message2, cipher, nonce, key, default, 0).IsTrue();
            message.SequenceEqual(message2).IsTrue();
            Aegis256.Encrypt(message3, cipher, nonce, key, default, 0);
            message.SequenceEqual(message3).IsTrue();
        }
    }
}
