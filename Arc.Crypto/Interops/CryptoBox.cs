// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// A low-level helper class for crypto_box functions in Libsodium, which implements public-key authenticated encryption.<br/>
/// Seed 32bytes, Secret key 32bytes, Public key 32bytes, Nonce 24bytes, Mac 16bytes.<br/>
/// Key exchange: X25519, Encryption: XSalsa20, Authentication: Poly1305.
/// </summary>
public static class CryptoBox
{
    /// <summary>
    /// The size of the seed in bytes.
    /// </summary>
    public const int SeedSize = 32; // crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES

    /// <summary>
    /// The size of the secret key in bytes.
    /// </summary>
    public const int SecretKeySize = 32; // crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES

    /// <summary>
    /// The size of the public key in bytes.
    /// </summary>
    public const int PublicKeySize = 32; // crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

    /// <summary>
    /// The size of the nonce in bytes.
    /// </summary>
    public const int NonceSize = 24; // crypto_box_curve25519xsalsa20poly1305_NONCEBYTES

    /// <summary>
    /// The size of the message authentication code in bytes.
    /// </summary>
    public const int MacSize = 16; // crypto_box_curve25519xsalsa20poly1305_MACBYTES

    /// <summary>
    /// The size of the raw X25519 shared secret in bytes.
    /// </summary>
    public const int SharedSecretSize = 32;

    /// <summary>
    /// Creates a new key pair (secret(32) and public(32) keys).
    /// </summary>
    /// <param name="secretKey32">The buffer to hold the secret key. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The buffer to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void CreateKeyPair(Span<byte> secretKey32, Span<byte> publicKey32)
    {
        if (secretKey32.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_box_keypair(publicKey32, secretKey32);
    }

    /// <summary>
    /// Creates a new key pair (public(32) and secret keys(32)) from a seed(32).
    /// </summary>
    /// <param name="seed32">The seed to generate the key pair. The size must be <see cref="SeedSize"/>(32 bytes).</param>
    /// <param name="secretKey32">The buffer to hold the secret key. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The buffer to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void CreateKeyPair(ReadOnlySpan<byte> seed32, Span<byte> secretKey32, Span<byte> publicKey32)
    {
        if (seed32.Length != SeedSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(seed32), SeedSize);
        }

        if (secretKey32.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_box_seed_keypair(publicKey32, secretKey32, seed32);
    }

    /// <summary>
    /// Encrypts a message using the given nonce(24), secret key(32), and public key(32).<br/>
    /// Ciphertext = Plaintext + MAC(16).
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="nonce24">The nonce to use for encryption. The size must be <see cref="NonceSize"/>(24 bytes).</param>
    /// <param name="secretKey32">The secret key to use for encryption. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The public key to use for encryption. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="ciphertext">The buffer to hold the encrypted message. The size must be plaintext length + <see cref="MacSize"/>(16 bytes).</param>
    /// <exception cref="CryptographicException">The recipient public key is invalid; the ciphertext buffer is cleared.</exception>
    public static void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> secretKey32, ReadOnlySpan<byte> publicKey32, Span<byte> ciphertext)
    {
        if (nonce24.Length != NonceSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(nonce24), NonceSize);
        }

        if (secretKey32.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (ciphertext.Length != (plaintext.Length + MacSize))
        {
            BaseHelper.ThrowSizeMismatchException(nameof(ciphertext), plaintext.Length + MacSize);
        }

        if (LibsodiumInterops.crypto_box_easy(ciphertext, plaintext, (ulong)plaintext.Length, nonce24, publicKey32, secretKey32) != 0)
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            throw new CryptographicException("The public key is not valid for key agreement.");
        }
    }

    /// <summary>
    /// Decrypts a ciphertext using the given nonce(24), secret key(32), and public key(32).<br/>
    /// Plaintext = Ciphertext - MAC(16).
    /// </summary>
    /// <param name="ciphertext">The encrypted message to decrypt.</param>
    /// <param name="nonce24">The nonce used for encryption. The size must be <see cref="NonceSize"/>(24 bytes).</param>
    /// <param name="secretKey32">The recipient secret key. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The sender public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="plaintext">The buffer to hold the decrypted message. The size must be ciphertext length - <see cref="MacSize"/>(16 bytes).</param>
    /// <returns><c>true</c> if decryption is successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> secretKey32, ReadOnlySpan<byte> publicKey32, Span<byte> plaintext)
    {
        if (ciphertext.Length < MacSize)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"The {nameof(ciphertext)} length must be at least {MacSize} bytes.");
        }

        if (nonce24.Length != NonceSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(nonce24), NonceSize);
        }

        if (secretKey32.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (plaintext.Length != (ciphertext.Length - MacSize))
        {
            BaseHelper.ThrowSizeMismatchException(nameof(plaintext), ciphertext.Length - MacSize);
        }

        return LibsodiumInterops.crypto_box_open_easy(plaintext, ciphertext, (ulong)ciphertext.Length, nonce24, publicKey32, secretKey32) == 0;
    }

    /// <summary>
    /// Computes a raw X25519 shared secret. Derive a session key from it with a KDF
    /// that binds both public keys in a consistent order and the protocol context.
    /// </summary>
    /// <param name="secretKey32">The secret key to use for key derivation. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The public key to use for key derivation. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="sharedSecret">The output buffer, exactly <see cref="SharedSecretSize"/> (32) bytes.</param>
    /// <exception cref="CryptographicException">The public key is invalid for key agreement; the output is cleared.</exception>
    public static void DeriveSharedSecret(ReadOnlySpan<byte> secretKey32, ReadOnlySpan<byte> publicKey32, Span<byte> sharedSecret)
    {
        if (secretKey32.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (sharedSecret.Length != SharedSecretSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(sharedSecret), SharedSecretSize);
        }

        if (LibsodiumInterops.crypto_scalarmult_curve25519(sharedSecret, secretKey32, publicKey32) != 0)
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw new CryptographicException("The public key is not valid for key agreement.");
        }
    }
}
