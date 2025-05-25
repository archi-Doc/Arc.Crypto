// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

public class Base64Test
{
    [Fact]
    public void TestEncodedLength()
    {
        for (var i = 0; i < 100; i++)
        {
            var length = Base64.Url.GetEncodedLength(i);
            var length2 = gfoidl.Base64.Base64.Url.GetEncodedLength(i);
            length.Is(length2);
            /*var length2 = Base64.Url.GetEncodedLength2(i);
            length2.Is(length);
            length2 = Base64.Url.GetEncodedLength3(i);
            length2.Is(length);*/
        }
    }

    [Fact]
    public void Test1()
    {
        var xo = new Xoshiro256StarStar(42);
        var rv = new RandomVault(x => xo.NextBytes(x));

        for (var i = 0; i < 300; i++)
        {
            var source = new byte[i];
            var written = 0;

            for (var j = 0; j < ((i / 2) + 1); j++)
            {
                rv.NextBytes(source);

                // Convert.ToBase64String
                var st = Convert.ToBase64String(source);

                // Byte array to string
                var st2 = Base64.Default.FromByteArrayToString(source);
                st.Equals(st2).IsTrue();

                // Byte array to utf8
                var utf8 = Base64.Default.FromByteArrayToUtf8(source);
                var st3 = Encoding.UTF8.GetString(utf8);
                st.Equals(st3).IsTrue();

                var bytes2 = Base64.Default.FromStringToByteArray(st);
                source.SequenceEqual(bytes2).IsTrue();

                var bytes3 = Base64.Default.FromUtf8ToByteArray(utf8);
                source.SequenceEqual(bytes3!).IsTrue();

                // Byte array to span
                Span<char> charSpan = new char[Base64.Default.GetEncodedLength(source.Length)];
                Base64.Default.FromByteArrayToSpan(source, charSpan, out _).IsTrue();
                st.Equals(charSpan.ToString()).IsTrue();

                Span<byte> byteSpan = new byte[Base64.Default.GetEncodedLength(source.Length)];
                Base64.Default.FromByteArrayToSpan(source, byteSpan, out _).IsTrue();
                utf8.SequenceEqual(byteSpan.ToArray()).IsTrue();

                Base64.Default.FromStringToSpan(charSpan, bytes2, out _).IsTrue();
                source.SequenceEqual(bytes2).IsTrue();

                Base64.Default.FromUtf8ToSpan(byteSpan, bytes2, out _).IsTrue();
                source.SequenceEqual(bytes2).IsTrue();

                // Url
                utf8 = Base64.Url.FromByteArrayToUtf8(source);
                bytes3 = Base64.Url.FromUtf8ToByteArray(utf8);
                source.SequenceEqual(bytes3!).IsTrue();

                st = Base64.Url.FromByteArrayToString(source);
                bytes3 = Base64.Url.FromStringToByteArray(st);
                source.SequenceEqual(bytes3!).IsTrue();

                // Byte array to span
                charSpan = new char[Base64.Url.GetEncodedLength(source.Length)];
                Base64.Url.FromByteArrayToSpan(source, charSpan, out written).IsTrue();
                st.Equals(charSpan.ToString()).IsTrue();

                byteSpan = new byte[Base64.Url.GetEncodedLength(source.Length)];
                Base64.Url.FromByteArrayToSpan(source, byteSpan, out _).IsTrue();
                utf8.SequenceEqual(byteSpan.ToArray()).IsTrue();

                Base64.Url.FromStringToSpan(charSpan, bytes2, out _).IsTrue();
                source.SequenceEqual(bytes2).IsTrue();

                Base64.Url.FromUtf8ToSpan(byteSpan, bytes2, out _).IsTrue();
                source.SequenceEqual(bytes2).IsTrue();
            }
        }
    }
}
