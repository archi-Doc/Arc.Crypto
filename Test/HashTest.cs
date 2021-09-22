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
        hash64 = Arc.Crypto.XXHash64.Hash64(data.AsSpan()); // As fast as FarmHash.
        hash32 = Arc.Crypto.FarmHash.Hash32(data.AsSpan()); // 32 bit version is slower than 64 bit version.
        hash32 = Arc.Crypto.XXHash32.Hash32(data.AsSpan()); // Same as above.
        hash32 = unchecked((uint)Arc.Crypto.FarmHash.Hash64(data.AsSpan())); // I recommend getting 64 bit and discarding half.
        hash32 = Arc.Crypto.Adler32.Hash32(data.AsSpan()); // Slow
        hash32 = Arc.Crypto.CRC32.Hash32(data.AsSpan()); // Slowest

        // IHash is an interface to get a hash of large data.
        // For XXHash64, IHash version is a bit slower than static method version.
        // For FarmHash64, IHash version is twice as slow. XXHash64 is recommended.
        var ihash = new Arc.Crypto.XXHash64();
        ihash.HashInitialize();
        ihash.HashUpdate(data);
        Assert.True(ihash.HashFinal().SequenceEqual(ihash.GetHash(data)));

        // Secure Hash Algorithm (SHA1, SHA2, SHA3 supported)
        var sha3_512 = new Arc.Crypto.SHA3_512();
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
        var crc32 = new CRC32();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt32(crc32.GetHash(span));
            var h2 = CRC32.Hash32(span);
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
        var xxh64 = new XXHash64();
        for (var n = 0; n < 1000; n++)
        {
            var span = data.AsSpan(0, n);
            var h = BitConverter.ToUInt64(xxh64.GetHash(span));
            var h2 = XXHash64.Hash64(span);
            Assert.Equal(h, h2);
        }

        this.TestHashUpdate_do(xxh64, data, random);

        // SHA1
        using var sha1 = new Arc.Crypto.SHA1();
        this.TestHashUpdate_do(sha1, data, random);

        // SHA2_256
        using var sha2_256 = new Arc.Crypto.SHA2_256();
        this.TestHashUpdate_do(sha2_256, data, random);

        // SHA2_384
        using var sha2_384 = new Arc.Crypto.SHA2_384();
        this.TestHashUpdate_do(sha2_384, data, random);

        // SHA2_512
        using var sha2_512 = new Arc.Crypto.SHA2_512();
        this.TestHashUpdate_do(sha2_512, data, random);

        // SHA3_256
        var sha3_256 = new Arc.Crypto.SHA3_256();
        this.TestHashUpdate_do(sha3_256, data, random);

        // SHA3_384
        var sha3_384 = new Arc.Crypto.SHA3_384();
        this.TestHashUpdate_do(sha3_384, data, random);

        // SHA3_512
        var sha3_512 = new Arc.Crypto.SHA3_512();
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
    public void TestSHA3()
    {
        var aa = new char[100];
        var utf8_empty = Encoding.UTF8.GetBytes(string.Empty);
        var utf8_abc = Encoding.UTF8.GetBytes("abc");
        var utf8_alphabet = Encoding.UTF8.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        var million_a = new char[1_000_000];
        Array.Fill(million_a, 'a');
        var utf8_million = Encoding.UTF8.GetBytes(million_a);
        byte[] hash;

        var sha3_256 = new SHA3_256();
        hash = sha3_256.GetHash(utf8_empty, 0, utf8_empty.Length);
        Assert.Equal(hash, "a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a".HexToByte());
        hash = sha3_256.GetHash(utf8_abc, 0, utf8_abc.Length);
        Assert.Equal(hash, "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532".HexToByte());
        hash = sha3_256.GetHash(utf8_alphabet, 0, utf8_alphabet.Length);
        Assert.Equal(hash, "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376".HexToByte());
        hash = sha3_256.GetHash(utf8_million, 0, utf8_million.Length);
        Assert.Equal(hash, "5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1".HexToByte());

        var sha3_384 = new SHA3_384();
        hash = sha3_384.GetHash(utf8_empty, 0, utf8_empty.Length);
        Assert.Equal(hash, "0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004".HexToByte());
        hash = sha3_384.GetHash(utf8_abc, 0, utf8_abc.Length);
        Assert.Equal(hash, "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25".HexToByte());
        hash = sha3_384.GetHash(utf8_alphabet, 0, utf8_alphabet.Length);
        Assert.Equal(hash, "991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22".HexToByte());
        hash = sha3_384.GetHash(utf8_million, 0, utf8_million.Length);
        Assert.Equal(hash, "eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340".HexToByte());

        var sha3_512 = new SHA3_512();
        hash = sha3_512.GetHash(utf8_empty, 0, utf8_empty.Length);
        Assert.Equal(hash, "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26".HexToByte());
        hash = sha3_512.GetHash(utf8_abc, 0, utf8_abc.Length);
        Assert.Equal(hash, "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0".HexToByte());
        hash = sha3_512.GetHash(utf8_alphabet, 0, utf8_alphabet.Length);
        Assert.Equal(hash, "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e".HexToByte());
        hash = sha3_512.GetHash(utf8_million, 0, utf8_million.Length);
        Assert.Equal(hash, "	3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87".HexToByte());
    }

    [Fact]
    public void TestXXHash64()
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
        var value = XXHash64.Hash64(bytes);
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
    public void TestCRC32()
    {
        uint value;
        value = CRC32.Hash32(string.Empty);
        Assert.Equal(0U, value);

        this.TestUtf8String_CRC32("123456789", 0xCBF43926);
        this.TestUtf8String_CRC32("The quick brown fox jumps over the lazy dog", 0x414FA339);

        var crc = new CRC32();
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

    private void TestUtf8String_CRC32(string text, uint expected)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        var value = CRC32.Hash32(bytes);
        Assert.Equal(expected, value);
    }
}
