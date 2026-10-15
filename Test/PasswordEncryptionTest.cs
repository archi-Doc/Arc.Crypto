// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class PasswordEncryptionTest
{
    private const int MessageLength = 64;
    private const int CipherLength = PasswordEncryption.SaltSize + MessageLength + PasswordEncryption.TagSize;

    [Theory]
    [InlineData(0)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(4096)]
    public void StringAndUtf8OverloadsAgree(int passwordLength)
    {
        var password = new string('p', passwordLength) + "日本語\0";
        var utf8 = Encoding.UTF8.GetBytes(password);
        var data = "payload"u8.ToArray();
        PasswordEncryption.Encrypt(data, password, out var ciphertext);
        Assert.True(PasswordEncryption.TryDecrypt(ciphertext, utf8, out var output));
        Assert.Equal(data, output);
        PasswordEncryption.Encrypt(data, utf8, out ciphertext);
        Assert.True(PasswordEncryption.TryDecrypt(ciphertext, password, out output));
        Assert.Equal(data, output);
        ciphertext[^1] ^= 1;
        Assert.False(PasswordEncryption.TryDecrypt(ciphertext, password, out output));
        Assert.Null(output);
        var destination = Enumerable.Repeat((byte)0xA5, data.Length).ToArray();
        Assert.False(PasswordEncryption.TryDecrypt(ciphertext, utf8, destination));
        Assert.All(destination, value => Assert.Equal(0, value));
    }

    [Fact]
    public void InvalidSizesAndEmptyMessages()
    {
        Assert.False(PasswordEncryption.TryDecrypt(new byte[47], "password", out _));
        Assert.False(PasswordEncryption.TryDecrypt(new byte[47], "password"u8, out _));
        Assert.False(PasswordEncryption.TryDecrypt(new byte[47], "password", Span<byte>.Empty));
        Assert.False(PasswordEncryption.TryDecrypt(new byte[47], "password"u8, Span<byte>.Empty));
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordEncryption.Encrypt("abc"u8, "password", new byte[50]));
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordEncryption.TryDecrypt(new byte[48], "password", new byte[1]));
        PasswordEncryption.Encrypt(ReadOnlySpan<byte>.Empty, string.Empty, out var cipher);
        Assert.True(PasswordEncryption.TryDecrypt(cipher, string.Empty, out var plain));
        Assert.Empty(plain!);
    }

    [Fact]
    public void Test1()
    {
        var password = "password";
        var wrongPassword = "password2";
        var data = Encoding.UTF8.GetBytes("data");

        PasswordEncryption.Encrypt(data, password, out var ciphertext);
        PasswordEncryption.TryDecrypt(ciphertext, password, out var plaintext).IsTrue();
        plaintext.AsSpan().SequenceEqual(data).IsTrue();
        PasswordEncryption.TryDecrypt(ciphertext, string.Empty, out _).IsFalse();
        PasswordEncryption.TryDecrypt(ciphertext, wrongPassword, out _).IsFalse();

        PasswordEncryption.Encrypt(data, string.Empty, out ciphertext);
        PasswordEncryption.TryDecrypt(ciphertext, string.Empty, out plaintext).IsTrue();
        plaintext.AsSpan().SequenceEqual(data).IsTrue();
        PasswordEncryption.TryDecrypt(ciphertext, wrongPassword, out _).IsFalse();
    }

    [Fact]
    public void FormatIsStable()
    {// Salt(32) + AEGIS-256 ciphertext + Tag(16); the salt is the nonce, and the key is Argon2id(password, salt[..16]) or salt[..32] for an empty password.
        var payload = "payload"u8.ToArray();
        var plaintext = new byte[payload.Length];

        PasswordEncryption.Encrypt(payload, ReadOnlySpan<byte>.Empty, out var ciphertext);
        ciphertext.Length.Is(PasswordEncryption.SaltSize + payload.Length + PasswordEncryption.TagSize);
        var salt = ciphertext.AsSpan(0, PasswordEncryption.SaltSize);
        Aegis256.TryDecrypt(plaintext, ciphertext.AsSpan(PasswordEncryption.SaltSize), salt, salt).IsTrue();
        plaintext.Is(payload);

        PasswordEncryption.Encrypt(payload, "pw"u8, out ciphertext);
        var key = new byte[Aegis256.KeySize];
        CryptoPasswordHash.DeriveKey("pw"u8, ciphertext.AsSpan(0, CryptoPasswordHash.SaltSize), key);
        Aegis256.TryDecrypt(plaintext, ciphertext.AsSpan(PasswordEncryption.SaltSize), ciphertext.AsSpan(0, PasswordEncryption.SaltSize), key).IsTrue();
        plaintext.Is(payload);

        // Every encryption uses a new random salt.
        PasswordEncryption.Encrypt(payload, ReadOnlySpan<byte>.Empty, out var ciphertext1);
        PasswordEncryption.Encrypt(payload, ReadOnlySpan<byte>.Empty, out var ciphertext2);
        ciphertext1.AsSpan(0, PasswordEncryption.SaltSize).SequenceEqual(ciphertext2.AsSpan(0, PasswordEncryption.SaltSize)).IsFalse();

        ciphertext1[^1] ^= 1;
        PasswordEncryption.TryDecrypt(ciphertext1, ReadOnlySpan<byte>.Empty, out byte[]? output).IsFalse();
        output.IsNull();

        Assert.Throws<ArgumentNullException>(() => PasswordEncryption.Encrypt(payload, (string)null!, out _));
    }

    [Theory]
    [InlineData(0, 8)]
    [InlineData(20, 20)]
    public void PasswordInSaltRegionIsReadBeforeTheSalt(int passwordOffset, int passwordLength)
    {// The salt used to overwrite such a password before key derivation, so the data could never be decrypted.
        var message = Enumerable.Range(0, MessageLength).Select(x => (byte)x).ToArray();
        var buffer = new byte[CipherLength];
        for (var i = 0; i < passwordLength; i++)
        {
            buffer[passwordOffset + i] = (byte)('a' + i);
        }

        var password = buffer.AsSpan(passwordOffset, passwordLength).ToArray();
        PasswordEncryption.Encrypt(message, buffer.AsSpan(passwordOffset, passwordLength), buffer);
        PasswordEncryption.TryDecrypt(buffer, password, out var decrypted).IsTrue();
        decrypted.Is(message);
    }

    [Theory]
    [InlineData(33)]
    [InlineData(40)]
    [InlineData(47)]
    [InlineData(48)]
    public void EncryptWithPlaintextAfterTheSalt(int offset)
    {// An empty password skips Argon2id, which keeps the test fast; overlap handling does not depend on the key.
        var message = Enumerable.Range(0, MessageLength).Select(x => (byte)(x * 3)).ToArray();
        var buffer = new byte[Math.Max(CipherLength, offset + MessageLength)];
        message.CopyTo(buffer, offset);
        PasswordEncryption.Encrypt(buffer.AsSpan(offset, MessageLength), ReadOnlySpan<byte>.Empty, buffer.AsSpan(0, CipherLength));
        var decrypted = new byte[MessageLength];
        PasswordEncryption.TryDecrypt(buffer.AsSpan(0, CipherLength), ReadOnlySpan<byte>.Empty, decrypted).IsTrue();
        decrypted.Is(message);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(16, true)]
    [InlineData(31, true)]
    [InlineData(32, true)]
    [InlineData(33, false)]
    [InlineData(48, false)]
    public void DecryptInPlace(int offset, bool supported)
    {
        var message = Enumerable.Range(0, MessageLength).Select(x => (byte)(x + 7)).ToArray();
        PasswordEncryption.Encrypt(message, ReadOnlySpan<byte>.Empty, out var ciphertext);
        var buffer = ciphertext.ToArray();
        if (supported)
        {
            PasswordEncryption.TryDecrypt(buffer, ReadOnlySpan<byte>.Empty, buffer.AsSpan(offset, MessageLength)).IsTrue();
            buffer.AsSpan(offset, MessageLength).ToArray().Is(message);
        }
        else
        {// The plaintext would overwrite ciphertext that has not been read yet.
            Assert.Throws<ArgumentException>(() => PasswordEncryption.TryDecrypt(buffer, ReadOnlySpan<byte>.Empty, buffer.AsSpan(offset, MessageLength)));
        }
    }
}
