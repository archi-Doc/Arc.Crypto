// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptoPasswordHashTest
{
    [Theory]
    [InlineData(0, 8192)]
    [InlineData(1, 0)]
    public void InvalidCostsThrow(int ops, int memory)
    {
        var opsLimit = (CryptoPasswordHash.OpsLimit)ops;
        var memLimit = (CryptoPasswordHash.MemLimit)memory;
        Assert.Throws<CryptographicException>(() => CryptoPasswordHash.GetHashString("password", opsLimit, memLimit));
        Assert.Throws<CryptographicException>(() => CryptoPasswordHash.GetHashString("password"u8, opsLimit, memLimit));
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
        const CryptoPasswordHash.OpsLimit Ops = (CryptoPasswordHash.OpsLimit)1;
        const CryptoPasswordHash.MemLimit Memory = (CryptoPasswordHash.MemLimit)8192;
        var password = new string('p', length) + "日本語\0";
        var utf8 = Encoding.UTF8.GetBytes(password);
        var hash = CryptoPasswordHash.GetHashString(password, Ops, Memory);
        Assert.True(CryptoPasswordHash.VerifyHashString(hash, password));
        Assert.True(CryptoPasswordHash.VerifyHashString(Encoding.UTF8.GetBytes(hash), utf8));
        Assert.False(CryptoPasswordHash.VerifyHashString(hash, password + "wrong"));

        var byteHash = CryptoPasswordHash.GetHashString(utf8, Ops, Memory);
        Assert.True(CryptoPasswordHash.VerifyHashString(byteHash, utf8));
        Assert.True(CryptoPasswordHash.VerifyHashString(Encoding.UTF8.GetString(byteHash), password));
        var padded = new byte[CryptoPasswordHash.HashStringLength];
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
}
