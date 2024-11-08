// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Helper class for calling crypto_secretbox function in Libsodium, which implements secret-key authenticated encryption.<br/>
/// Encryption: XSalsa20 stream cipher, Authentication: Poly1305 MAC.
/// </summary>
public static class CryptoSecretBox
{
    public const int KeySize = 32;
    public const int NonceSize = 24; // crypto_secretbox_xsalsa20poly1305_NONCEBYTES
    public const int MacSize = 16; // crypto_secretbox_MACBYTES = crypto_secretbox_xsalsa20poly1305_MACBYTES

    public static void CreateKey(Span<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_secretbox_keygen(key);
    }

    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> cipher)
    {
        if (nonce.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        if (cipher.Length != message.Length + MacSize)
        {
            throw new ArgumentOutOfRangeException(nameof(cipher));
        }

        LibsodiumInterops.crypto_secretbox_easy(cipher, message, (ulong)message.Length, nonce, key);
    }

    public static void Decrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, Span<byte> message)
    {
        if (cipher.Length < MacSize)
        {
            throw new ArgumentOutOfRangeException(nameof(cipher));
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        if (key.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        if (message.Length != cipher.Length - MacSize)
        {
            throw new ArgumentOutOfRangeException(nameof(message));
        }

        LibsodiumInterops.crypto_secretbox_open_easy(message, cipher, (ulong)cipher.Length, nonce, key);
    }
}
