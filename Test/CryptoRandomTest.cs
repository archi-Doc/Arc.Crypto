// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptoRandomTest
{
    [Fact]
    public void NextBytesFillsExactlyTheDestination()
    {
        var a = new byte[64];
        var b = new byte[64];
        CryptoRandom.NextBytes(a);
        CryptoRandom.NextBytes(b);
        a.SequenceEqual(b).IsFalse(); // A false failure has probability 2^-512.
        a.All(x => x == 0).IsFalse();
        b.All(x => x == 0).IsFalse();

        CryptoRandom.NextBytes(Span<byte>.Empty);

        var buffer = new byte[1000];
        CryptoRandom.NextBytes(buffer.AsSpan(1, 998));
        buffer[0].Is((byte)0);
        buffer[999].Is((byte)0);
        buffer.Skip(1).Take(998).Count(x => x == 0).Is(x => x < 40); // About 3.9 zero bytes are expected; 40 or more has probability below 2^-80.
    }
}
