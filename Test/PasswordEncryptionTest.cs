// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class PasswordEncryptionTest
{
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
}
