// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Buffers.Text;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Arc.Crypto;
using Xunit;

namespace Test;

/// <summary>
/// Encoder contracts for <see cref="FastBase64"/> and <see cref="FastBase64Url"/>: output, untouched trailing
/// destination space, exception parameter names and the length limits.
/// </summary>
public class FastBase64EncodeTest
{
    [Fact]
    public void EncodeMatchesConvertAndLeavesTrailingSpaceUntouched()
    {
        const byte ByteMarker = 0xA5;
        const char CharMarker = 'ꖥ';
        var random = new Random(20261015);
        for (var length = 0; length <= 300; length++)
        {
            var data = new byte[length];
            random.NextBytes(data);
            var standard = Convert.ToBase64String(data);
            var url = standard.TrimEnd('=').Replace('+', '-').Replace('/', '_');

            foreach (var isUrl in new[] { false, true })
            {
                var expected = isUrl ? url : standard;
                var utf8 = new byte[expected.Length + 64];
                utf8.AsSpan().Fill(ByteMarker);
                var written = isUrl ? FastBase64Url.Encode(data, utf8) : FastBase64.Encode(data, utf8);
                written.Is(expected.Length);
                Encoding.ASCII.GetString(utf8, 0, written).Is(expected);
                Assert.True(utf8.AsSpan(written).IndexOfAnyExcept(ByteMarker) < 0, $"Length {length}, url {isUrl}: UTF-8 output overran.");

                var chars = new char[expected.Length + 64];
                chars.AsSpan().Fill(CharMarker);
                written = isUrl ? FastBase64Url.Encode(data, chars) : FastBase64.Encode(data, chars);
                written.Is(expected.Length);
                new string(chars, 0, written).Is(expected);
                Assert.True(chars.AsSpan(written).IndexOfAnyExcept(CharMarker) < 0, $"Length {length}, url {isUrl}: UTF-16 output overran.");

                (isUrl ? FastBase64Url.EncodeToString(data) : FastBase64.EncodeToString(data)).Is(expected);
            }
        }
    }

    [Fact]
    public void DestinationTooSmallReportsPublicParameterName()
    {
        var data = new byte[3];
        Assert.Throws<ArgumentException>(() => FastBase64.Encode(data, new byte[3])).ParamName.Is("utf8Destination");
        Assert.Throws<ArgumentException>(() => FastBase64.Encode(data, new char[3])).ParamName.Is("charsDestination");
        Assert.Throws<ArgumentException>(() => FastBase64Url.Encode(data, new byte[3])).ParamName.Is("utf8Destination");
        Assert.Throws<ArgumentException>(() => FastBase64Url.Encode(data, new char[3])).ParamName.Is("charsDestination");
    }

    [Fact]
    public void LengthHelpersMatchBcl()
    {
        for (var n = 0; n <= 1000; n++)
        {
            FastBase64.GetEncodedLength(n).Is(Base64.GetMaxEncodedToUtf8Length(n));
            FastBase64Url.GetEncodedLength(n).Is(Base64Url.GetEncodedLength(n));
            FastBase64Url.GetMaxDecodedLength(FastBase64Url.GetEncodedLength(n)).Is(n); // Exact for unpadded input.
        }

        // System.Buffers.Text accepts at most 1610612733 input bytes.
        FastBase64.GetEncodedLength(1610612733).Is(Base64.GetMaxEncodedToUtf8Length(1610612733));
        FastBase64Url.GetEncodedLength(1610612733).Is(Base64Url.GetEncodedLength(1610612733));
    }

    [Theory]
    [InlineData(1610612733)]
    [InlineData(1610612734)]
    [InlineData(1610612735)]
    [InlineData(1610612736)]
    [InlineData(int.MaxValue)]
    public void EncodedLengthAboveInt32Throws(int byteCount)
    {
        var standard = (new BigInteger(byteCount) + 2) / 3 * 4;
        var url = ((new BigInteger(byteCount) * 4) + 2) / 3; // ceil(4n / 3)

        if (standard <= int.MaxValue)
        {
            FastBase64.GetEncodedLength(byteCount).Is((int)standard);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => FastBase64.GetEncodedLength(byteCount)).ParamName.Is("byteCount");
        }

        if (url <= int.MaxValue)
        {
            FastBase64Url.GetEncodedLength(byteCount).Is((int)url);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => FastBase64Url.GetEncodedLength(byteCount)).ParamName.Is("byteCount");
        }

        var maxDecoded = (int)(new BigInteger(byteCount) * 3 / 4);
        FastBase64.GetMaxDecodedLength(byteCount).Is(maxDecoded);
        FastBase64Url.GetMaxDecodedLength(byteCount).Is(maxDecoded);
    }

    /// <summary>
    /// Encodes to UTF-16 around 2^30 output characters, where <see cref="Convert.TryToBase64Chars"/> overflows.
    /// Needs about 3 GB of memory, so it runs only on request; run it also with DOTNET_EnableSSE42=0
    /// to cover the BCL delegation path.
    /// </summary>
    [Fact(Explicit = true)]
    public void EncodeToCharsAroundTwoToTheThirtyChars()
    {
        const int MaxLength = 3 << 28; // 805,306,368 bytes -> 2^30 chars
        const int ChunkLength = 3 << 20; // Multiple of 3: only the last chunk is padded.

        var data = GC.AllocateUninitializedArray<byte>(MaxLength);
        var words = MemoryMarshal.Cast<byte, uint>(data.AsSpan());
        for (var i = 0; i < words.Length; i++)
        {
            words[i] = (uint)i * 2654435761u;
        }

        var chars = GC.AllocateUninitializedArray<char>(FastBase64.GetEncodedLength(MaxLength));
        var expected = new char[FastBase64.GetEncodedLength(ChunkLength)];
        foreach (var length in new[] { MaxLength - 3, MaxLength - 2, MaxLength })
        {
            foreach (var isUrl in new[] { false, true })
            {
                var input = data.AsSpan(0, length);
                var written = isUrl ? FastBase64Url.Encode(input, chars) : FastBase64.Encode(input, chars);
                written.Is(isUrl ? FastBase64Url.GetEncodedLength(length) : FastBase64.GetEncodedLength(length));

                for (var offset = 0; offset < length; offset += ChunkLength)
                {
                    var chunk = input.Slice(offset, Math.Min(ChunkLength, length - offset));
                    int count;
                    if (isUrl)
                    {
                        count = Base64Url.EncodeToChars(chunk, expected);
                    }
                    else
                    {
                        Convert.TryToBase64Chars(chunk, expected, out count).IsTrue();
                    }

                    Assert.True(
                        chars.AsSpan(offset / 3 * 4, count).SequenceEqual(expected.AsSpan(0, count)),
                        $"Length {length}, url {isUrl}: mismatch at input offset {offset}.");
                }
            }
        }
    }
}
