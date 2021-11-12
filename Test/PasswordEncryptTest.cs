// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Arc.Crypto;
using Xunit;

namespace Test;

public class PasswordEncryptTest
{
    [Fact]
    public void Test1()
    {
        const int DataN = 100;
        const int PassN = 80;

        var data = new byte[DataN];
        for (var i = 0; i < DataN; i++)
        {
            data[i] = (byte)i;
        }

        var pass = new string[PassN];
        var sb = new StringBuilder();
        for (var i = 0; i < PassN; i++)
        {
            pass[i] = sb.ToString();
            sb.Append((char)('!' + i));
        }

        for (var i = 0; i < DataN; i++)
        {
            var dataSpan = data.AsSpan(0, i);
            for (var j = 0; j < PassN; j++)
            {
                var encrypted = PasswordEncrypt.Encrypt(dataSpan, pass[j]);
                PasswordEncrypt.TryDecrypt(encrypted, pass[j], out var decrypted).IsTrue();
                dataSpan.SequenceEqual(decrypted.Span).IsTrue();
            }
        }
    }

    [Fact]
    public void Test2()
    {
        var data = new byte[] { 0, 1, 2, 3, };
        byte[] encrypted;

        encrypted = PasswordEncrypt.Encrypt(data, "1");
        PasswordEncrypt.IsEncryptedWithPassword(encrypted).IsTrue();
        PasswordEncrypt.TryDecrypt(encrypted, "1", out _).IsTrue();
        PasswordEncrypt.TryDecrypt(encrypted, "2", out _).IsFalse();

        encrypted = PasswordEncrypt.Encrypt(data, string.Empty);
        PasswordEncrypt.IsEncryptedWithPassword(encrypted).IsFalse();
        PasswordEncrypt.TryDecrypt(encrypted, "1", out _).IsTrue();
        PasswordEncrypt.TryDecrypt(encrypted, string.Empty, out _).IsTrue();
        PasswordEncrypt.TryDecrypt(encrypted, null, out _).IsTrue();

        encrypted = PasswordEncrypt.Encrypt(data, null);
        PasswordEncrypt.IsEncryptedWithPassword(encrypted).IsFalse();
        PasswordEncrypt.TryDecrypt(encrypted, "1", out _).IsTrue();
        PasswordEncrypt.TryDecrypt(encrypted, string.Empty, out _).IsTrue();
        PasswordEncrypt.TryDecrypt(encrypted, null, out _).IsTrue();
    }
}
