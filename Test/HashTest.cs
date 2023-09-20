// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

#pragma warning disable SA1202 // Elements should be ordered by access

namespace Test;

public class HashTest
{
    [Fact]
    public void QuickStart()
    {
        var data = new byte[100];
        ulong hash64;
        uint hash32;
        byte[] array;

        hash64 = Arc.Crypto.FarmHash.Hash64(data.AsSpan()); // The fastest and best algorithm.
        hash64 = Arc.Crypto.XxHash64.Hash64(data.AsSpan()); // As fast as FarmHash.
        hash32 = Arc.Crypto.FarmHash.Hash32(data.AsSpan()); // 32 bit version is slower than 64 bit version.
        hash32 = Arc.Crypto.XXHash32.Hash32(data.AsSpan()); // Same as above.
        hash32 = unchecked((uint)Arc.Crypto.FarmHash.Hash64(data.AsSpan())); // I recommend getting 64 bit and discarding half.
        hash32 = Arc.Crypto.Adler32.Hash32(data.AsSpan()); // Slow
        hash32 = Arc.Crypto.Crc32.Hash32(data.AsSpan()); // Slowest

        // IHash is an interface to get a hash of large data.
        // For XxHash64, IHash version is a bit slower than static method version.
        // For FarmHash64, IHash version is twice as slow. XxHash64 is recommended.
        var ihash = new Arc.Crypto.XxHash64();
        ihash.HashInitialize();
        ihash.HashUpdate(data);
        Assert.True(ihash.HashFinal().SequenceEqual(ihash.GetHash(data)));

        // Secure Hash Algorithm (SHA1, SHA2, SHA3 supported)
        var sha3_512 = new Arc.Crypto.Sha3_512();
        array = sha3_512.GetHash(data.AsSpan());

        sha3_512.HashInitialize(); // Another way
        sha3_512.HashUpdate(data.AsSpan());
        Assert.True(sha3_512.HashFinal().SequenceEqual(array));
    }

    [Fact]
    public void TestHashUpdate()
    {
        const int N = 1_000_000;
        var random = new Random(42);
        var data = new byte[N];
        random.NextBytes(data);

        // CRC-32
        var crc32 = new Crc32();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt32(crc32.GetHash(span));
            var h2 = Crc32.Hash32(span);
            Assert.Equal(h, h2);
        }

        this.TestHashUpdate_do(crc32, data, random);

        // Adler-32
        var adler32 = new Adler32();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt32(adler32.GetHash(span));
            var h2 = Adler32.Hash32(span);
            Assert.Equal(h, h2);
        }

        this.TestHashUpdate_do(adler32, data, random);

        // FarmHash
        var farm = new FarmHash();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt64(farm.GetHash(span));
            var h2 = FarmHash.Hash64(span);
            Assert.Equal(h, h2);
        }

        this.TestHashUpdate_do(farm, data, random);

        // xxHash32
        var xxh32 = new XXHash32();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt32(xxh32.GetHash(span));
            var h2 = XXHash32.Hash32(span);
            Assert.Equal(h, h2);
        }

        this.TestHashUpdate_do(xxh32, data, random);

        // xxHash64
        var xxh64 = new XxHash64();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt64(xxh64.GetHash(span));
            var h2 = XxHash64.Hash64(span);
            Assert.Equal(h, h2);
        }

        this.TestHashUpdate_do(xxh64, data, random);

        // Sha1
        using var sha1 = new Arc.Crypto.Sha1();
        this.TestHashUpdate_do(sha1, data, random);

        // Sha2_256
        using var sha2_256 = new Arc.Crypto.Sha2_256();
        this.TestHashUpdate_do(sha2_256, data, random);

        // Sha2_384
        using var sha2_384 = new Arc.Crypto.Sha2_384();
        this.TestHashUpdate_do(sha2_384, data, random);

        // Sha2_512
        using var sha2_512 = new Arc.Crypto.Sha2_512();
        this.TestHashUpdate_do(sha2_512, data, random);

        // Sha3_256
        var sha3_256 = new Arc.Crypto.Sha3_256();
        this.TestHashUpdate_do(sha3_256, data, random);

        // Sha3_384
        var sha3_384 = new Arc.Crypto.Sha3_384();
        this.TestHashUpdate_do(sha3_384, data, random);

        // Sha3_512
        var sha3_512 = new Arc.Crypto.Sha3_512();
        this.TestHashUpdate_do(sha3_512, data, random);
    }

    private void TestHashUpdate_do(IHash hash, byte[] data, Random random)
    {
        this.TestHashUpdate_core(hash, data, 10, random);
        this.TestHashUpdate_core(hash, data, 100, random);
        this.TestHashUpdate_core(hash, data, 1_000, random);
        this.TestHashUpdate_core(hash, data, 10_000, random);
        this.TestHashUpdate_core(hash, data, data.Length, random);
    }

    private void TestHashUpdate_core(IHash hash, byte[] data, int length, Random random)
    {
        var randomSize = new int[] { 10, 100, 1_000, 10_000, 100_000 }.Where(n => n <= length).ToArray();

        var reference = hash.GetHash(data, 0, length); // data.AsSpan(0, length)
        for (var n = 0; n < 20; n++)
        {
            hash.HashInitialize();
            int start = 0;
            while (start < length)
            {
                var size = this.GetRandomSize(random, randomSize);
                if ((start + size) > length)
                {
                    size = length - start;
                }

                hash.HashUpdate(data, start, size); // data.AsSpan(start, size)
                start += size;
            }

            Assert.Equal(reference, hash.HashFinal());
        }
    }

    private int GetRandomSize(Random random, int[] randomSize)
    {
        int range = random.Next(randomSize.Length);
        return random.Next(1, randomSize[range]);
    }

    [Fact]
    public void TestSha2()
    {
        using var sha2 = new Arc.Crypto.Sha2_256();

        var random = new Random(42);
        byte[] h;
        byte[] h2;
        byte[] h4 = new byte[32];
        for (var length = 0; length < 1_000; length++)
        {
            var buffer = new byte[length];
            for (var i = 0; i < 100; i++)
            {
                random.NextBytes(buffer);

                h = sha2.GetHash(buffer, 0, length);
                h2 = Sha2Helper.Get256_ByteArray(buffer);
                h.SequenceEqual(h2).IsTrue();
            }

            h = sha2.GetHash(buffer, 0, length);

            var h3 = Sha2Helper.Get256_UInt64(buffer);
            var b = h4.AsSpan();
            BitConverter.TryWriteBytes(b, h3.Hash0);
            b = b.Slice(8);
            BitConverter.TryWriteBytes(b, h3.Hash1);
            b = b.Slice(8);
            BitConverter.TryWriteBytes(b, h3.Hash2);
            b = b.Slice(8);
            BitConverter.TryWriteBytes(b, h3.Hash3);
            h.SequenceEqual(h4).IsTrue();

            Sha2Helper.Get256_Span(buffer, h4);
            h.SequenceEqual(h4).IsTrue();
        }
    }

    [Fact]
    public void TestSha3()
    {
        var aa = new char[100];
        var utf8_empty = Encoding.UTF8.GetBytes(string.Empty);
        var utf8_abc = Encoding.UTF8.GetBytes("abc");
        var utf8_alphabet = Encoding.UTF8.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        var million_a = new char[1_000_000];
        Array.Fill(million_a, 'a');
        var utf8_million = Encoding.UTF8.GetBytes(million_a);
        byte[] hash;

        var sha3_256 = new Sha3_256();
        hash = sha3_256.GetHash(utf8_empty, 0, utf8_empty.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
        Sha3Helper.Get256_ByteArray(utf8_empty).SequenceEqual(hash).IsTrue();

        hash = sha3_256.GetHash(utf8_abc, 0, utf8_abc.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
        Sha3Helper.Get256_ByteArray(utf8_abc).SequenceEqual(hash).IsTrue();

        hash = sha3_256.GetHash(utf8_alphabet, 0, utf8_alphabet.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"));
        Sha3Helper.Get256_ByteArray(utf8_alphabet).SequenceEqual(hash).IsTrue();

        hash = sha3_256.GetHash(utf8_million, 0, utf8_million.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"));
        Sha3Helper.Get256_ByteArray(utf8_million).SequenceEqual(hash).IsTrue();

        var sha3_384 = new Sha3_384();
        hash = sha3_384.GetHash(utf8_empty, 0, utf8_empty.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"));
        Sha3Helper.Get384_ByteArray(utf8_empty).SequenceEqual(hash).IsTrue();

        hash = sha3_384.GetHash(utf8_abc, 0, utf8_abc.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"));
        Sha3Helper.Get384_ByteArray(utf8_abc).SequenceEqual(hash).IsTrue();

        hash = sha3_384.GetHash(utf8_alphabet, 0, utf8_alphabet.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22"));
        Sha3Helper.Get384_ByteArray(utf8_alphabet).SequenceEqual(hash).IsTrue();

        hash = sha3_384.GetHash(utf8_million, 0, utf8_million.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"));
        Sha3Helper.Get384_ByteArray(utf8_million).SequenceEqual(hash).IsTrue();

        var sha3_512 = new Sha3_512();
        hash = sha3_512.GetHash(utf8_empty, 0, utf8_empty.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"));
        Sha3Helper.Get512_ByteArray(utf8_empty).SequenceEqual(hash).IsTrue();

        hash = sha3_512.GetHash(utf8_abc, 0, utf8_abc.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
        Sha3Helper.Get512_ByteArray(utf8_abc).SequenceEqual(hash).IsTrue();

        hash = sha3_512.GetHash(utf8_alphabet, 0, utf8_alphabet.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"));
        Sha3Helper.Get512_ByteArray(utf8_alphabet).SequenceEqual(hash).IsTrue();

        hash = sha3_512.GetHash(utf8_million, 0, utf8_million.Length);
        Assert.Equal(hash, Hex.FromStringToByteArray("3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"));
        Sha3Helper.Get512_ByteArray(utf8_million).SequenceEqual(hash).IsTrue();
    }

    [Fact]
    public void TestXxHash64()
    {
        this.TestUtf8String_xxHash64(string.Empty, 0xef46db3751d8e999UL);
        this.TestUtf8String_xxHash64("a", 0xd24ec4f1a98c6e5bUL);
        this.TestUtf8String_xxHash64("123", 0x3c697d223fa7e885UL);
        this.TestUtf8String_xxHash64("123456789012345", 0xc377d78ade001a3cUL);
        this.TestUtf8String_xxHash64("The quick brown fox jumps over the lazy dog", 0x0b242d361fda71bcUL);
    }

    private void TestUtf8String_xxHash64(string text, ulong expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var value = XxHash64.Hash64(bytes);
        Assert.Equal(expected, value);
    }

    [Fact]
    public void TestXXHash32()
    {
        this.TestUtf8String_xxHash32(string.Empty, 0x02cc5d05);
        this.TestUtf8String_xxHash32("a", 0x550d7456);
        this.TestUtf8String_xxHash32("123", 0xb6855437);
        this.TestUtf8String_xxHash32("123456789012345", 0xda7b17e8);
        this.TestUtf8String_xxHash32("The quick brown fox jumps over the lazy dog", 0xe85ea4de);
    }

    private void TestUtf8String_xxHash32(string text, uint expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var value = XXHash32.Hash32(bytes);
        Assert.Equal(expected, value);
    }

    [Fact]
    public void TestFarmHash()
    {
        uint value;
        value = FarmHash.Hash32(string.Empty);
        Assert.Equal((uint)0xdc56d17a, value);

        this.TestUtf8String_FarmHash32("abc", 0x2f635ec7);
        this.TestUtf8String_FarmHash32("message digest", 0x0c10337e);
        this.TestUtf8String_FarmHash32("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x3bb6b2a4);
    }

    [Fact]
    public void TestAdler32()
    {
        uint value;
        value = Adler32.Hash32(string.Empty);
        Assert.Equal(1U, value);

        this.TestUtf8String_Adler32("abc", 0x024d0127);
        this.TestUtf8String_Adler32("message digest", 0x29750586);
        this.TestUtf8String_Adler32("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x8adb150c);

        var adler = new Adler32();
        this.TestUtf8StringSplit(adler, "abc", 1, 0x024d0127);
        this.TestUtf8StringSplit(adler, "message digest", 4, 0x29750586);
        this.TestUtf8StringSplit(adler, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 10, 0x8adb150c);
    }

    private void TestUtf8String_FarmHash32(string text, uint expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var value = FarmHash.Hash32(bytes);
        Assert.Equal(expected, value);
    }

    private void TestUtf8String_Adler32(string text, uint expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var value = Adler32.Hash32(bytes);
        Assert.Equal(expected, value);
    }

    [Fact]
    public void TestCrc32()
    {
        uint value;
        value = Crc32.Hash32(string.Empty);
        Assert.Equal(0U, value);

        this.TestUtf8String_Crc32("123456789", 0xCBF43926);
        this.TestUtf8String_Crc32("The quick brown fox jumps over the lazy dog", 0x414FA339);

        var crc = new Crc32();
        this.TestUtf8StringSplit(crc, "123456789", 2, 0xCBF43926);
        this.TestUtf8StringSplit(crc, "123456789", 4, 0xCBF43926);
        this.TestUtf8StringSplit(crc, "The quick brown fox jumps over the lazy dog", 4, 0x414FA339);
        this.TestUtf8StringSplit(crc, "The quick brown fox jumps over the lazy dog", 10, 0x414FA339);
    }

    private void TestUtf8StringSplit(IHash ha, string text, int splitOffset, uint expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);

        // Transform function.
        ha.HashInitialize();
        ha.HashUpdate(bytes.AsSpan(0, splitOffset));
        ha.HashUpdate(bytes.AsSpan(splitOffset, bytes.Length - splitOffset));
        var value = BitConverter.ToUInt32(ha.HashFinal());
        Assert.Equal(expected, value);

        // ComputeHash function.
        value = BitConverter.ToUInt32(ha.GetHash(bytes));
        Assert.Equal(expected, value);
    }

    private void TestUtf8String_Crc32(string text, uint expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var value = Crc32.Hash32(bytes);
        Assert.Equal(expected, value);
    }
}
