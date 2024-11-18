// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class PasswordEncryptionTest
{
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
