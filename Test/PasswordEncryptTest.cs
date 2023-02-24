// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
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
        var a = PasswordEncrypt.GetPasswordHint("a");
        var a2 = PasswordEncrypt.GetPasswordHint("a");
        a.Is(a2);

        var b = PasswordEncrypt.GetPasswordHint("b");
        b.IsNot(a);

        var c = PasswordEncrypt.GetPasswordHint("a1b2c3d4");
        var c2 = PasswordEncrypt.GetPasswordHint("a1b2c3d4");
        c.IsNot(a);
        c.Is(c2);
    }
}
