// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Provides cryptographically secure random bytes using the Libsodium random generator.
/// </summary>
public static class CryptoRandom
{
    /// <summary>
    /// Fills the specified span with cryptographically secure random bytes.
    /// </summary>
    /// <param name="destination">The span to fill with random bytes.</param>
    public static void NextBytes(Span<byte> destination)
    {
        LibsodiumInterops.randombytes_buf(destination, (UIntPtr)destination.Length);
    }
}
