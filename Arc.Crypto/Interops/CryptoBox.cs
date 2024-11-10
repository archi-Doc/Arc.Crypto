// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Drawing;

namespace Arc.Crypto;

/// <summary>
/// Helper class for calling crypto_box function in Libsodium, which implements public-key authenticated encryption.<br/>
/// Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305.
/// </summary>
public static class CryptoBox
{
    public const int SeedSize = 32; // crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
    public const int SecretKeySize = 32; // crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
    public const int PublicKeySize = 32; // crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
    public const int NonceSize = 24; // crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
    public const int MacSize = 16; // crypto_box_curve25519xsalsa20poly1305_MACBYTES

    public static void CreateKey(Span<byte> secretKey, Span<byte> publicKey)
    {
        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        LibsodiumInterops.crypto_box_keypair(publicKey, secretKey);
    }

    public static void CreateKey(ReadOnlySpan<byte> seed, Span<byte> secretKey, Span<byte> publicKey)
    {
        if (seed.Length != SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed), SeedSize);
        }

        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        LibsodiumInterops.crypto_box_seed_keypair(publicKey, secretKey, seed);
    }

    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey, Span<byte> cipher)
    {
        if (nonce.Length != NonceSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(nonce), NonceSize);
        }

        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        if (cipher.Length != (message.Length + MacSize))
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(cipher), message.Length + MacSize);
        }

        LibsodiumInterops.crypto_box_easy(cipher, message, (ulong)message.Length, nonce, publicKey, secretKey);
    }

    public static void Decrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey, Span<byte> message)
    {
        if (cipher.Length < MacSize)
        {
            throw new ArgumentOutOfRangeException($"The {nameof(cipher)} length must be at least {MacSize} bytes.");
        }

        if (nonce.Length != NonceSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(nonce), NonceSize);
        }

        if (secretKey.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey), SecretKeySize);
        }

        if (publicKey.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey), PublicKeySize);
        }

        if (message.Length != (cipher.Length - MacSize))
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(message), cipher.Length - MacSize);
        }

        LibsodiumInterops.crypto_box_open_easy(message, cipher, (ulong)cipher.Length, nonce, publicKey, secretKey);
    }
}
