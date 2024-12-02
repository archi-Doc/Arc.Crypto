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
        var rv = new RandomVault(x => xo.NextBytes(x), false);

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
        var bytes = Base32Sort.Default.FromStringToByteArray("test");
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
        var bytes2 = Base32Sort.Reference.FromStringToByteArray("0123456abcefgHiJKOxIyzlo1234loOABC");
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
        var st = Base32Sort.Reference.FromByteArrayToString(source);

        var length = (source.Length * 8 / 5) + (((source.Length * 8) % 5) == 0 ? 0 : 1);
        st.Length.Is(length);

        // String to byte array
        var b = Base32Sort.Reference.FromStringToByteArray(st);
        source.SequenceEqual(b).IsTrue();
        b = Base32Sort.Reference.FromStringToByteArray(st.ToLower()); // Lower case
        source.SequenceEqual(b).IsTrue();

        // Utf8
        var utf8 = Base32Sort.Reference.FromByteArrayToUtf8(source);
        var b2 = Base32Sort.Reference.FromUtf8ToByteArray(utf8)!;
        b2.SequenceEqual(b).IsTrue();
        UTF8Encoding.UTF8.GetBytes(st).SequenceEqual(utf8).IsTrue();

        // Byte array to span
        Span<char> charSpan = new char[Base32Sort.GetEncodedLength(source.Length)];
        Base32Sort.Reference.FromByteArrayToSpan(source, charSpan, out _).IsTrue();
        st.Equals(charSpan.ToString()).IsTrue();

        Span<byte> byteSpan = new byte[Base32Sort.GetEncodedLength(source.Length)];
        Base32Sort.Reference.FromByteArrayToSpan(source, byteSpan, out _).IsTrue();
        utf8.SequenceEqual(byteSpan.ToArray()).IsTrue();

        Base32Sort.Reference.FromStringToSpan(charSpan, b, out _).IsTrue();
        source.SequenceEqual(b).IsTrue();

        Base32Sort.Reference.FromUtf8ToSpan(byteSpan, b, out _).IsTrue();
        source.SequenceEqual(b).IsTrue();

        // Table
        var st2 = Base32Sort.Table.FromByteArrayToString(source);
        st2.Is(st);
        b2 = Base32Sort.Table.FromStringToByteArray(st);
        b2.SequenceEqual(b).IsTrue();
        b2 = Base32Sort.Table.FromStringToByteArray(st.ToLower()); // Lower case
        b2.SequenceEqual(b).IsTrue();

        utf8 = Base32Sort.Table.FromByteArrayToUtf8(source);
        b2 = Base32Sort.Table.FromUtf8ToByteArray(utf8)!;
        b2.SequenceEqual(b).IsTrue();
        UTF8Encoding.UTF8.GetBytes(st).SequenceEqual(utf8).IsTrue();

        // Byte array to span
        Base32Sort.Table.FromByteArrayToSpan(source, charSpan, out _).IsTrue();
        st.Equals(charSpan.ToString()).IsTrue();

        Base32Sort.Table.FromByteArrayToSpan(source, byteSpan, out _).IsTrue();
        utf8.SequenceEqual(byteSpan.ToArray()).IsTrue();

        Base32Sort.Table.FromStringToSpan(charSpan, b, out _).IsTrue();
        source.SequenceEqual(b).IsTrue();

        Base32Sort.Table.FromUtf8ToSpan(byteSpan, b, out _).IsTrue();
        source.SequenceEqual(b).IsTrue();
    }
}
