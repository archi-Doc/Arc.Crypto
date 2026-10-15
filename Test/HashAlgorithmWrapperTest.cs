// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

namespace Test;

public class HashAlgorithmWrapperTest
{
    public static TheoryData<string> WrapperNames => new() { "SHA1", "SHA2-256", "SHA2-384", "SHA2-512", };

    [Theory]
    [MemberData(nameof(WrapperNames))]
    public void ArrayOverloadsHonorOffset(string name)
    {
        var buffer = new byte[300];
        new Xoshiro256StarStar(31).NextBytes(buffer);
        var slice = buffer.AsSpan(7, 200);
        var expected = SystemHash(name, slice);

        using var hash = CreateWrapper(name);
        hash.HashName.Is(name);
        hash.HashBits.Is((uint)expected.Length * 8);
        hash.IsCryptographic.IsTrue();
        Assert.Equal(expected, hash.GetHash(buffer, 7, 200));
        Assert.Equal(expected, hash.GetHash(slice));

        hash.HashInitialize();
        hash.HashUpdate(buffer, 7, 100);
        hash.HashUpdate(buffer, 107, 100);
        Assert.Equal(expected, hash.HashFinal());

        Assert.ThrowsAny<ArgumentException>(() => hash.GetHash(new byte[4], 5, 1));
        Assert.ThrowsAny<ArgumentException>(() => hash.GetHash(new byte[4], 1, 4));
        Assert.ThrowsAny<ArgumentException>(() => hash.HashUpdate(new byte[4], 1, 4));
        Assert.Throws<ArgumentNullException>(() => hash.GetHash(null!, 0, 0));
    }

    [Theory]
    [MemberData(nameof(WrapperNames))]
    public void WrapperThrowsAfterDispose(string name)
    {
        var hash = CreateWrapper(name);
        hash.Dispose();
        hash.Dispose();

        // The one-shot overrides use pooled instances, so only the explicit check stops them after disposal.
        Assert.Throws<ObjectDisposedException>(() => hash.GetHash("abc"u8));
        Assert.Throws<ObjectDisposedException>(() => hash.GetHash(new byte[3], 0, 3));
        Assert.Throws<ObjectDisposedException>(() => hash.HashUpdate("abc"u8));
        Assert.Throws<ObjectDisposedException>(() => hash.HashUpdate(new byte[3], 0, 3));
        Assert.Throws<ObjectDisposedException>(() => hash.HashFinal());
    }

    [Fact]
    public void CustomWrapperUsesDefaults()
    {
        using var md5 = new Md5Wrapper();
        md5.HashName.Is("Wrapper");
        md5.HashBits.Is(0u);
        md5.IsCryptographic.IsFalse();

        var data = new byte[5000];
        new Xoshiro256StarStar(32).NextBytes(data);
        foreach (var length in new[] { 0, 1, 5000 })
        {
            Assert.Equal(MD5.HashData(data.AsSpan(0, length)), md5.GetHash(data.AsSpan(0, length)));
        }

        // The default HashData uses the wrapped instance, so it consumes and resets an incremental calculation in progress.
        md5.HashInitialize();
        md5.HashUpdate("abc"u8);
        Assert.Equal(MD5.HashData("abc"u8.ToArray().Concat(data).ToArray()), md5.GetHash(data));
        Assert.Equal(MD5.HashData(ReadOnlySpan<byte>.Empty), md5.HashFinal());

        using var broken = new BrokenWrapper();
        Assert.Throws<CryptographicException>(() => broken.GetHash("abc"u8));
    }

    private static HashAlgorithmWrapper CreateWrapper(string name) => name switch
    {
        "SHA1" => new Arc.Crypto.Sha1(),
        "SHA2-256" => new Sha2_256(),
        "SHA2-384" => new Sha2_384(),
        "SHA2-512" => new Sha2_512(),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static byte[] SystemHash(string name, ReadOnlySpan<byte> data) => name switch
    {
        "SHA1" => SHA1.HashData(data),
        "SHA2-256" => SHA256.HashData(data),
        "SHA2-384" => SHA384.HashData(data),
        "SHA2-512" => SHA512.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private sealed class Md5Wrapper : HashAlgorithmWrapper
    {
        public Md5Wrapper()
        {
            this.HashAlgorithm = MD5.Create();
        }
    }

    private sealed class BrokenWrapper : HashAlgorithmWrapper
    {
        public BrokenWrapper()
        {
            this.HashAlgorithm = SHA256.Create();
        }

        protected override int HashData(ReadOnlySpan<byte> source, Span<byte> destination) => 0;
    }
}
