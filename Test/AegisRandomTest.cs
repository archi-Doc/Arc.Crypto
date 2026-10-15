// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Reflection;
using Arc.Crypto;
using Xunit;

namespace Test;

public class AegisRandomTest
{
    [Fact]
    public void InstancesAndRefillsProduceDifferentStreams()
    {
        var first = new AegisRandom();
        var second = new AegisRandom();
        var block1 = new byte[1024];
        var block2 = new byte[1024];
        var other = new byte[1024];
        first.NextBytes(block1);
        first.NextBytes(block2);
        second.NextBytes(other);

        // Each instance is keyed from RandomNumberGenerator, and every refill uses a new key and nonce.
        block1.SequenceEqual(other).IsFalse();
        block1.SequenceEqual(block2).IsFalse();
        block1.SequenceEqual(new byte[1024]).IsFalse();
    }

    [Fact]
    public void EmptyRequestConsumesNothing()
    {
        var random = new AegisRandom();
        var position = typeof(AegisRandom).GetField("position", BindingFlags.Instance | BindingFlags.NonPublic)!;
        random.NextBytes(new byte[1000]);
        var before = (int)position.GetValue(random)!;

        random.NextBytes(Span<byte>.Empty);
        ((int)position.GetValue(random)!).Is(before);
    }
}
