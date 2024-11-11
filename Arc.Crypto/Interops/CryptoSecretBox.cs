// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// Helper class for crypto_secretbox functions in Libsodium, which implements secret-key authenticated encryption.<br/>
/// Key 32bytes, Nonce 24bytes, MAC 16bytes.<br/>
/// Encryption: XSalsa20 stream cipher, Authentication: Poly1305 MAC.
/// </summary>
public static class CryptoSecretBox
{
    /// <summary>
    /// The size of the key in bytes.
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    /// The size of the nonce in bytes.
    /// </summary>
    public const int NonceSize = 24; // crypto_secretbox_xsalsa20poly1305_NONCEBYTES

    /// <summary>
    /// The size of the message authentication code in bytes.
    /// </summary>
    public const int MacSize = 16; // crypto_secretbox_MACBYTES = crypto_secretbox_xsalsa20poly1305_MACBYTES

    /// <summary>
    /// Generates a new secret key.
    /// </summary>
    /// <param name="key">A span to hold the generated key. The size must be <see cref="KeySize"/>(32 bytes).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the key span is not 32 bytes long.</exception>
    public static void CreateKey(Span<byte> key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        LibsodiumInterops.crypto_secretbox_keygen(key);
    }

    /// <summary>
    /// Encrypts a message using the specified nonce and key.
    /// </summary>
    /// <param name="message">The message to encrypt.</param>
    /// <param name="nonce24">The nonce to use for encryption. The size must be <see cref="NonceSize"/>(24 bytes).</param>
    /// <param name="key32">The key to use for encryption. The size must be <see cref="KeySize"/>(32 bytes).</param>
    /// <param name="cipher">A span to hold the encrypted message. Must be message length + <see cref="MacSize"/>(16 bytes).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the nonce, key, or cipher span lengths are incorrect.</exception>
    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key32, Span<byte> cipher)
    {
        if (nonce24.Length != NonceSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(nonce24), NonceSize);
        }

        if (key32.Length != KeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(key32), KeySize);
        }

        if (cipher.Length != message.Length + MacSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(cipher), message.Length + MacSize);
        }

        LibsodiumInterops.crypto_secretbox_easy(cipher, message, (ulong)message.Length, nonce24, key32);
    }

    /// <summary>
    /// Decrypts a cipher using the specified nonce and key.
    /// </summary>
    /// <param name="cipher">The encrypted message to decrypt. Must be at least 16 bytes long.</param>
    /// <param name="nonce24">The nonce to use for decryption. The size must be <see cref="NonceSize"/>(24 bytes).</param>
    /// <param name="key32">The key to use for decryption. The size must be <see cref="KeySize"/>(32 bytes).</param>
    /// <param name="message">A span to hold the decrypted message. Must be cipher length - <see cref="MacSize"/>(16 bytes).</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the cipher, nonce, key, or message span lengths are incorrect.</exception>
    public static void Decrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> key32, Span<byte> message)
    {
        if (cipher.Length < MacSize)
        {
            throw new ArgumentOutOfRangeException($"The {nameof(cipher)} length must be at least {MacSize} bytes.");
        }

        if (nonce24.Length != NonceSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(nonce24), NonceSize);
        }

        if (key32.Length != KeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(key32), KeySize);
            throw new ArgumentOutOfRangeException(nameof(key32));
        }

        if (message.Length != cipher.Length - MacSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(message), cipher.Length - MacSize);
        }

        LibsodiumInterops.crypto_secretbox_open_easy(message, cipher, (ulong)cipher.Length, nonce24, key32);
    }
}
