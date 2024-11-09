// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

public static class CryptoRandom
{
    /// <summary>
    /// Fills the provided buffer with cryptographically secure random bytes.
    /// </summary>
    /// <param name="buffer">The buffer to fill with random bytes.</param>
    public static void NextBytes(Span<byte> buffer)
    {
        LibsodiumInterops.randombytes_buf(buffer, (int)buffer.Length);
    }
}
