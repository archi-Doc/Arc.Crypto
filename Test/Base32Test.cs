// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Base32Test
{
    [Fact]
    public void Test1()
    {
        this.TestByteArray(new byte[] { });
        this.TestByteArray(new byte[] { 0, });
        this.TestByteArray(new byte[] { 1, });
        this.TestByteArray(new byte[] { 2, });
        this.TestByteArray(new byte[] { 1, 2, });
        this.TestByteArray(new byte[] { 1, 2, 3, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, });
        this.TestByteArray(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, });
    }

    [Fact]
    public void Test2()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(x => xo.NextBytes(x));

        for (var i = 0; i < 300; i++)
        {
            var bytes = new byte[i];

            for (var j = 0; j < ((i / 2) + 1); j++)
            {
                rv.NextBytes(bytes);
                this.TestByteArray(bytes);
            }
        }
    }

    [Fact]
    public void Test3()
    {
        // T=25, E=13, S=24: 11001 01101 11000 11001 -> 0xCB 0x71 (the last four bits do not complete a byte).
        var bytes = Base32Sort.Default.FromStringToByteArray("test");
        Assert.Equal(new byte[] { 0xCB, 0x71, }, bytes);
        Assert.Equal(bytes, Base32Sort.Reference.FromStringToByteArray("TEST"));

        bytes = Base32Sort.Reference.FromStringToByteArray("*****");
        bytes.Length.Is(0);

        for (var i = 1; i < 50; i++)
        {
            var utf16 = new string('*', i);
            bytes = Base32Sort.Reference.FromStringToByteArray(utf16);
            bytes.Length.Is(0);
            bytes = Base32Sort.Table.FromStringToByteArray(utf16);
            bytes.Length.Is(0);

            var utf8 = UTF8Encoding.UTF8.GetBytes(utf16);
            bytes = Base32Sort.Reference.FromUtf8ToByteArray(utf8);
            bytes.Length.Is(0);
            bytes = Base32Sort.Table.FromUtf8ToByteArray(utf8);
            bytes.Length.Is(0);
        }

        bytes = Base32Sort.Reference.FromStringToByteArray("0123456abcefgHiJKOxIyzlo1234loOABC");
        bytes.Length.Is(Base32Sort.GetDecodedLength(34));
        var bytes2 = Base32Sort.Table.FromStringToByteArray("0123456abcefgHiJKOxIyzlo1234loOABC");
        bytes2.SequenceEqual(bytes).IsTrue();

        bytes2 = Base32Sort.Reference.FromStringToByteArray("o123456abcefgH1JKOx1yz1o1234looabc");
        bytes2.SequenceEqual(bytes).IsTrue();
        bytes2 = Base32Sort.Reference.FromStringToByteArray("O123456abcefgHIJKOxIyz101234lo0ABC");
        bytes2.SequenceEqual(bytes).IsTrue();
        bytes2 = Base32Sort.Reference.FromStringToByteArray("0123456ABcefgHiJK0x1yzlol234loOABC");
        bytes2.SequenceEqual(bytes).IsTrue();

        bytes2 = Base32Sort.Table.FromStringToByteArray("o123456abcefgH1JKOx1yz1o1234looabc");
        bytes2.SequenceEqual(bytes).IsTrue();
        bytes2 = Base32Sort.Table.FromStringToByteArray("O123456abcefgHIJKOxIyz101234lo0ABC");
        bytes2.SequenceEqual(bytes).IsTrue();
        bytes2 = Base32Sort.Table.FromStringToByteArray("0123456ABcefgHiJK0x1yzlol234loOABC");
        bytes2.SequenceEqual(bytes).IsTrue();
    }

    private void TestByteArray(byte[] source)
    {
        // Byte array to string
        var st = Base32Sort.Reference.FromBytesToString(source);

        var length = (source.Length * 8 / 5) + (((source.Length * 8) % 5) == 0 ? 0 : 1);
        st.Length.Is(length);

        // String to byte array
        var b = Base32Sort.Reference.FromStringToByteArray(st);
        source.SequenceEqual(b).IsTrue();
        b = Base32Sort.Reference.FromStringToByteArray(st.ToLower()); // Lower case
        source.SequenceEqual(b).IsTrue();

        // Utf8
        var utf8 = Base32Sort.Reference.FromBytesToUtf8(source);
        var b2 = Base32Sort.Reference.FromUtf8ToByteArray(utf8)!;
        b2.SequenceEqual(b).IsTrue();
        UTF8Encoding.UTF8.GetBytes(st).SequenceEqual(utf8).IsTrue();

        // Spans: each destination has one spare element and is refilled with a marker before every call,
        // so a call that writes nothing, too little or too much fails.
        foreach (var converter in new[] { Base32Sort.Reference, Base32Sort.Table, })
        {
            var charSpan = new char[length + 1];
            charSpan.AsSpan().Fill('#');
            (converter.FromBytesToSpan(source, charSpan, out var written) && written == length).IsTrue();
            charSpan.AsSpan(0, length).SequenceEqual(st).IsTrue();
            (charSpan[^1] == '#').IsTrue();

            var byteSpan = new byte[length + 1];
            byteSpan.AsSpan().Fill(0xAA);
            (converter.FromBytesToSpan(source, byteSpan, out written) && written == length).IsTrue();
            byteSpan.AsSpan(0, length).SequenceEqual(utf8).IsTrue();
            (byteSpan[^1] == 0xAA).IsTrue();

            var decoded = new byte[source.Length + 1];
            decoded.AsSpan().Fill(0xAA);
            (converter.FromStringToSpan(st, decoded, out written) && written == source.Length).IsTrue();
            decoded.AsSpan(0, source.Length).SequenceEqual(source).IsTrue();
            (decoded[^1] == 0xAA).IsTrue();

            decoded.AsSpan().Fill(0x55);
            (converter.FromUtf8ToSpan(utf8, decoded, out written) && written == source.Length).IsTrue();
            decoded.AsSpan(0, source.Length).SequenceEqual(source).IsTrue();
            (decoded[^1] == 0x55).IsTrue();
        }

        // Table
        var st2 = Base32Sort.Table.FromBytesToString(source);
        st2.Is(st);
        b2 = Base32Sort.Table.FromStringToByteArray(st);
        b2.SequenceEqual(b).IsTrue();
        b2 = Base32Sort.Table.FromStringToByteArray(st.ToLower()); // Lower case
        b2.SequenceEqual(b).IsTrue();

        utf8 = Base32Sort.Table.FromBytesToUtf8(source);
        b2 = Base32Sort.Table.FromUtf8ToByteArray(utf8)!;
        b2.SequenceEqual(b).IsTrue();
        UTF8Encoding.UTF8.GetBytes(st).SequenceEqual(utf8).IsTrue();
    }
}
