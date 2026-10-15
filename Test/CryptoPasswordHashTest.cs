// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptoPasswordHashTest
{
    // Small costs keep the tests fast; these are not production defaults.
    private const CryptoPasswordHash.OperationLimit FastOps = (CryptoPasswordHash.OperationLimit)1;
    private const CryptoPasswordHash.MemoryLimit FastMemory = (CryptoPasswordHash.MemoryLimit)8192;

    [Theory]
    [InlineData(0, 8192)]
    [InlineData(1, 0)]
    public void InvalidCostsThrow(int ops, int memory)
    {
        var operationLimit = (CryptoPasswordHash.OperationLimit)ops;
        var memoryLimit = (CryptoPasswordHash.MemoryLimit)memory;
        Assert.Throws<CryptographicException>(() => CryptoPasswordHash.GetHashString("password", operationLimit, memoryLimit));
        Assert.Throws<CryptographicException>(() => CryptoPasswordHash.GetUtf8HashString("password"u8, operationLimit, memoryLimit));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(4096)]
    public void PasswordOverloadsAgree(int length)
    {
        // Small costs keep boundary testing fast; these are not production defaults.
        const CryptoPasswordHash.OperationLimit Ops = (CryptoPasswordHash.OperationLimit)1;
        const CryptoPasswordHash.MemoryLimit Memory = (CryptoPasswordHash.MemoryLimit)8192;
        var password = new string('p', length) + "日本語\0";
        var utf8 = Encoding.UTF8.GetBytes(password);
        var hash = CryptoPasswordHash.GetHashString(password, Ops, Memory);
        Assert.True(CryptoPasswordHash.VerifyHashString(hash, password));
        Assert.True(CryptoPasswordHash.VerifyHashString(Encoding.UTF8.GetBytes(hash), utf8));
        Assert.False(CryptoPasswordHash.VerifyHashString(hash, password + "wrong"));

        var byteHash = CryptoPasswordHash.GetUtf8HashString(utf8, Ops, Memory);
        Assert.True(CryptoPasswordHash.VerifyHashString(byteHash, utf8));
        Assert.True(CryptoPasswordHash.VerifyHashString(Encoding.UTF8.GetString(byteHash), password));
        var padded = new byte[CryptoPasswordHash.MaxHashStringLength];
        byteHash.CopyTo(padded, 0);
        Assert.True(CryptoPasswordHash.VerifyHashString(padded, utf8));

        var salt = new byte[CryptoPasswordHash.SaltSize];
        var charKey = new byte[32];
        var byteKey = new byte[32];
        CryptoPasswordHash.DeriveKey(password.AsSpan(), salt, charKey, Ops, Memory);
        CryptoPasswordHash.DeriveKey(utf8, salt, byteKey, Ops, Memory);
        Assert.Equal(byteKey, charKey);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(129)]
    public void MalformedHashIsRejected(int length)
    {
        var hash = new string('x', length);
        Assert.False(CryptoPasswordHash.VerifyHashString(hash, "password"));
        Assert.False(CryptoPasswordHash.VerifyHashString(Encoding.UTF8.GetBytes(hash), "password"u8));
    }

    [Fact]
    public void DeriveKeyMatchesHashString()
    {// crypto_pwhash_str encodes the algorithm, the costs, the salt and an Argon2id output of the same parameters.
        var hashString = CryptoPasswordHash.GetHashString("password", FastOps, FastMemory);
        hashString.StartsWith("$argon2id$v=19$m=8,t=1,p=1$", StringComparison.Ordinal).IsTrue();
        var parts = hashString.Split('$');
        parts.Length.Is(6);
        var salt = FromUnpaddedBase64(parts[4]);
        var hash = FromUnpaddedBase64(parts[5]);
        salt.Length.Is(CryptoPasswordHash.SaltSize);
        hash.Length.Is(32);

        var key = new byte[32];
        CryptoPasswordHash.DeriveKey("password", salt, key, FastOps, FastMemory);
        key.Is(hash);
        CryptoPasswordHash.DeriveKey("password"u8, salt, key, FastOps, FastMemory);
        key.Is(hash);

        // The default costs are the interactive limits (2 passes, 64 MiB).
        var utf8HashString = CryptoPasswordHash.GetUtf8HashString("p"u8);
        Encoding.ASCII.GetString(utf8HashString).StartsWith("$argon2id$v=19$m=65536,t=2,p=1$", StringComparison.Ordinal).IsTrue();
        utf8HashString.Contains((byte)0).IsFalse();

        static byte[] FromUnpaddedBase64(string s) => Convert.FromBase64String(s.PadRight((s.Length + 3) / 4 * 4, '='));
    }

    [Fact]
    public void DeriveKeyValidatesArguments()
    {
        var salt = new byte[CryptoPasswordHash.SaltSize];
        var key = new byte[32];
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPasswordHash.DeriveKey("password", new byte[15], key, FastOps, FastMemory));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPasswordHash.DeriveKey("password", new byte[17], key, FastOps, FastMemory));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPasswordHash.DeriveKey("password", salt, new byte[15], FastOps, FastMemory));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPasswordHash.DeriveKey("password"u8, new byte[15], key, FastOps, FastMemory));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPasswordHash.DeriveKey("password"u8, new byte[17], key, FastOps, FastMemory));
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoPasswordHash.DeriveKey("password"u8, salt, new byte[15], FastOps, FastMemory));

        // A failed derivation clears the key, also when the key overlaps the salt.
        foreach (var (ops, memory) in new[] { (0, 8192), (1, 0) })
        {
            Array.Fill(key, (byte)0xA5);
            Assert.Throws<CryptographicException>(() => CryptoPasswordHash.DeriveKey("password"u8, salt, key, (CryptoPasswordHash.OperationLimit)ops, (CryptoPasswordHash.MemoryLimit)memory));
            key.All(x => x == 0).IsTrue();

            Array.Fill(key, (byte)0xA5);
            Assert.Throws<CryptographicException>(() => CryptoPasswordHash.DeriveKey("password", key.AsSpan(0, CryptoPasswordHash.SaltSize), key, (CryptoPasswordHash.OperationLimit)ops, (CryptoPasswordHash.MemoryLimit)memory));
            key.All(x => x == 0).IsTrue();
        }
    }

    [Theory]
    [InlineData(32, 0, 0)]
    [InlineData(32, 0, 16)]
    [InlineData(32, 4, 0)]
    [InlineData(32, 0, 31)]
    [InlineData(100, 0, 50)]
    public void DeriveKeyIntoBufferOverlappingSalt(int keyLength, int keyOffset, int saltOffset)
    {// Libsodium writes the output before reading the salt; an overlapping key used to be random.
        var salt = Enumerable.Range(1, CryptoPasswordHash.SaltSize).Select(x => (byte)x).ToArray();
        var expected = new byte[keyLength];
        CryptoPasswordHash.DeriveKey("password"u8, salt, expected, FastOps, FastMemory);

        var buffer = new byte[Math.Max(keyOffset + keyLength, saltOffset + CryptoPasswordHash.SaltSize)];
        salt.CopyTo(buffer, saltOffset);
        CryptoPasswordHash.DeriveKey("password"u8, buffer.AsSpan(saltOffset, CryptoPasswordHash.SaltSize), buffer.AsSpan(keyOffset, keyLength), FastOps, FastMemory);
        buffer.AsSpan(keyOffset, keyLength).ToArray().Is(expected);

        buffer = new byte[buffer.Length];
        salt.CopyTo(buffer, saltOffset);
        CryptoPasswordHash.DeriveKey("password", buffer.AsSpan(saltOffset, CryptoPasswordHash.SaltSize), buffer.AsSpan(keyOffset, keyLength), FastOps, FastMemory);
        buffer.AsSpan(keyOffset, keyLength).ToArray().Is(expected);
    }

    [Fact]
    public void DeriveKeyIntoBufferOverlappingPassword()
    {
        var salt = new byte[CryptoPasswordHash.SaltSize];
        var password = Enumerable.Range(0, 40).Select(x => (byte)('a' + (x % 26))).ToArray();
        var expected = new byte[32];
        CryptoPasswordHash.DeriveKey(password, salt, expected, FastOps, FastMemory);

        // Key in the middle of the password.
        var buffer = password.ToArray();
        CryptoPasswordHash.DeriveKey(buffer, salt, buffer.AsSpan(8, 32), FastOps, FastMemory);
        buffer.AsSpan(8, 32).ToArray().Is(expected);

        // Derive in place over the password; this used to throw and leave the buffer cleared.
        var password32 = password.AsSpan(0, 32).ToArray();
        CryptoPasswordHash.DeriveKey(password32, salt, expected, FastOps, FastMemory);
        buffer = password32.ToArray();
        CryptoPasswordHash.DeriveKey(buffer, salt, buffer, FastOps, FastMemory);
        buffer.Is(expected);
    }

    [Fact]
    public void UnpairedSurrogatesAreReplaced()
    {// Kept for compatibility: string passwords are encoded with Encoding.UTF8, which maps unpaired surrogates to U+FFFD.
        var salt = new byte[CryptoPasswordHash.SaltSize];
        var expected = new byte[32];
        var key = new byte[32];
        CryptoPasswordHash.DeriveKey("a\uFFFD", salt, expected, FastOps, FastMemory);
        CryptoPasswordHash.DeriveKey("a\uD800", salt, key, FastOps, FastMemory);
        key.Is(expected);
        CryptoPasswordHash.DeriveKey("a\uDFFF", salt, key, FastOps, FastMemory);
        key.Is(expected);
        CryptoPasswordHash.DeriveKey(new byte[] { (byte)'a', 0xEF, 0xBF, 0xBD }, salt, key, FastOps, FastMemory);
        key.Is(expected);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(128)]
    [InlineData(200)]
    public void NullArgumentsThrow(int hashLength)
    {// A null password used to be accepted (returning false) when the hash string was too long.
        var ex = Assert.Throws<ArgumentNullException>(() => CryptoPasswordHash.VerifyHashString(new string('x', hashLength), null!));
        ex.ParamName.Is("password");
        ex = Assert.Throws<ArgumentNullException>(() => CryptoPasswordHash.VerifyHashString((string)null!, "x"));
        ex.ParamName.Is("hashString");
        ex = Assert.Throws<ArgumentNullException>(() => CryptoPasswordHash.GetHashString(null!, FastOps, FastMemory));
        ex.ParamName.Is("password");
    }
}
