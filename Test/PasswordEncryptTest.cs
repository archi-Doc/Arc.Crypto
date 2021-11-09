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
        var data = new byte[] { 0, 1, 2, 3 };
        var encrypted = PasswordEncrypt.Encrypt(data, "pass1");
        PasswordEncrypt.TryDecrypt(encrypted, "pass1", out var decrypted);
    }
}
