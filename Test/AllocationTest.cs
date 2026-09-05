// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto;
using Arc.Crypto.EC;
using Xunit;

namespace Test;

public class AllocationTest
{
    [Fact]
    public void SeedValidationDoesNotAllocate()
    {
        var seed = Enumerable.Repeat((byte)0x5A, 32).ToArray();
        var curve = P256K1Curve.Instance;
        for (var i = 0; i < 100; i++)
        {
            Assert.True(curve.IsValidSeed(seed));
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        var valid = true;
        for (var i = 0; i < 1_000; i++)
        {
            valid &= curve.IsValidSeed(seed);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(valid);
        Assert.Equal(0, allocated);
    }

    [Theory]
    [InlineData(32)]
    [InlineData(4096)]
    public void Base32AllocatesOnlyTheReturnedString(int length)
    {
        var data = new byte[length];
        foreach (var converter in new[] { Base32Sort.Reference, Base32Sort.Table, })
        {
            for (var i = 0; i < 100; i++)
            {
                converter.FromByteArrayToString(data);
            }

            var encodedLength = Base32Sort.GetEncodedLength(length);
            var before = GC.GetAllocatedBytesForCurrentThread();
            var plain = new string('0', encodedLength);
            var stringAllocation = GC.GetAllocatedBytesForCurrentThread() - before;
            GC.KeepAlive(plain);
            before = GC.GetAllocatedBytesForCurrentThread();
            var encoded = converter.FromByteArrayToString(data);
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.Equal(stringAllocation, allocated);
            Assert.Equal(plain, encoded);
        }
    }

    [Fact]
    public void PasswordStringSpanOverloadDoesNotAllocateAfterWarmup()
    {
        var cipher = new byte[PasswordEncryption.SaltSize + PasswordEncryption.TagSize];
        foreach (var password in new[] { "password", new string('p', 512), })
        {
            PasswordEncryption.Encrypt(ReadOnlySpan<byte>.Empty, password, cipher);
            PasswordEncryption.TryDecrypt(cipher, password, Span<byte>.Empty);
            var before = GC.GetAllocatedBytesForCurrentThread();
            PasswordEncryption.Encrypt(ReadOnlySpan<byte>.Empty, password, cipher);
            var success = PasswordEncryption.TryDecrypt(cipher, password, Span<byte>.Empty);
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.True(success);
            Assert.Equal(0, allocated);
        }
    }
}
