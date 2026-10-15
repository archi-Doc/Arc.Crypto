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
        var curve = Secp256k1Curve.Instance;
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
                converter.FromBytesToString(data);
            }

            var encodedLength = Base32Sort.GetEncodedLength(length);
            var before = GC.GetAllocatedBytesForCurrentThread();
            var plain = new string('0', encodedLength);
            var stringAllocation = GC.GetAllocatedBytesForCurrentThread() - before;
            GC.KeepAlive(plain);
            before = GC.GetAllocatedBytesForCurrentThread();
            var encoded = converter.FromBytesToString(data);
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

    [Fact]
    public void AegisDoesNotAllocate()
    {
        var key128 = new byte[Aegis128L.KeySize];
        var nonce128 = new byte[Aegis128L.NonceSize];
        var key256 = new byte[Aegis256.KeySize];
        var nonce256 = new byte[Aegis256.NonceSize];
        var message = new byte[77]; // Full blocks plus a partial block for both ciphers.
        var ad = new byte[13]; // A partial associated-data block.
        var cipher16 = new byte[message.Length + 16];
        var cipher32 = new byte[message.Length + 32];
        var decrypted = new byte[message.Length];
        new Random(42).NextBytes(message);

        var success = true;
        for (var i = 0; i < 100; i++)
        {
            success &= Run();
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 1_000; i++)
        {
            success &= Run();
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(success);
        Assert.Equal(0, allocated);

        bool Run()
        {
            var ok = true;
            Aegis256.Encrypt(cipher16, message, nonce256, key256, ad, 16);
            ok &= Aegis256.TryDecrypt(decrypted, cipher16, nonce256, key256, ad, 16);
            Aegis256.Encrypt(cipher32, message, nonce256, key256, ad, 32);
            ok &= Aegis256.TryDecrypt(decrypted, cipher32, nonce256, key256, ad, 32);
            ok &= !Aegis256.TryDecrypt(decrypted, cipher32, nonce256, key256, default, 32); // Authentication failure.

            Aegis128L.Encrypt(cipher16, message, nonce128, key128, ad, 16);
            ok &= Aegis128L.TryDecrypt(decrypted, cipher16, nonce128, key128, ad, 16);
            Aegis128L.Encrypt(cipher32, message, nonce128, key128, ad, 32);
            ok &= Aegis128L.TryDecrypt(decrypted, cipher32, nonce128, key128, ad, 32);
            ok &= !Aegis128L.TryDecrypt(decrypted, cipher32, nonce128, key128, default, 32); // Authentication failure.

            // The portable backends, which the dispatch skips when hardware AES is available.
            Aegis256Soft.Encrypt(cipher32, message, nonce256, key256, ad, 32);
            ok &= Aegis256Soft.Decrypt(decrypted, cipher32, nonce256, key256, ad, 32);
            Aegis128LSoft.Encrypt(cipher32, message, nonce128, key128, ad, 32);
            ok &= Aegis128LSoft.Decrypt(decrypted, cipher32, nonce128, key128, ad, 32);
            return ok;
        }
    }

    [Fact]
    public void AegisRandomNextBytesDoesNotAllocate()
    {
        var random = new AegisRandom();
        var buffer = new byte[5000]; // Each call crosses several 1024-byte refills; the RandomNumberGenerator store is reloaded every 64 refills.
        for (var i = 0; i < 100; i++)
        {
            random.NextBytes(buffer);
        }

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var i = 0; i < 1_000; i++)
        {
            random.NextBytes(buffer);
        }

        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(0, allocated);
    }
}
