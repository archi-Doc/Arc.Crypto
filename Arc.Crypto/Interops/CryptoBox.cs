// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Benchmark.Obsolete.Ed25519;

namespace Arc.Crypto;

/// <summary>
/// Helper class for crypto_box functions in Libsodium, which implements public-key authenticated encryption.<br/>
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
    /// Creates a new key pair (secret and public  keys).
    /// </summary>
    /// <param name="secretKey32">The buffer to hold the secret key. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The buffer to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void CreateKey(Span<byte> secretKey32, Span<byte> publicKey32)
    {
        if (secretKey32.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_box_keypair(publicKey32, secretKey32);
    }

    /// <summary>
    /// Creates a new key pair (public and secret keys) from a seed.
    /// </summary>
    /// <param name="seed32">The seed to generate the key pair. The size must be <see cref="SeedSize"/>(32 bytes).</param>
    /// <param name="secretKey32">The buffer to hold the secret key. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The buffer to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void CreateKey(ReadOnlySpan<byte> seed32, Span<byte> secretKey32, Span<byte> publicKey32)
    {
        if (seed32.Length != SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed32), SeedSize);
        }

        if (secretKey32.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_box_seed_keypair(publicKey32, secretKey32, seed32);
    }

    /// <summary>
    /// Encrypts a message using the given nonce, secret key, and public key.
    /// </summary>
    /// <param name="message">The message to encrypt.</param>
    /// <param name="nonce24">The nonce to use for encryption. The size must be <see cref="NonceSize"/>(24 bytes).</param>
    /// <param name="secretKey32">The secret key to use for encryption. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The public key to use for encryption. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="cipher">The buffer to hold the encrypted message. The size must be message length + <see cref="MacSize"/>(16 bytes).</param>
    public static void Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> secretKey32, ReadOnlySpan<byte> publicKey32, Span<byte> cipher)
    {
        if (nonce24.Length != NonceSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(nonce24), NonceSize);
        }

        if (secretKey32.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (cipher.Length != (message.Length + MacSize))
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(cipher), message.Length + MacSize);
        }

        LibsodiumInterops.crypto_box_easy(cipher, message, (ulong)message.Length, nonce24, publicKey32, secretKey32);
    }

    /// <summary>
    /// Decrypts a cipher using the given nonce, secret key, and public key.
    /// </summary>
    /// <param name="cipher">The encrypted message to decrypt.</param>
    /// <param name="nonce24">The nonce used for encryption. The size must be <see cref="NonceSize"/>(24 bytes).</param>
    /// <param name="secretKey32">The secret key used for encryption. The size must be <see cref="SecretKeySize"/>(32 bytes).</param>
    /// <param name="publicKey32">The public key used for encryption. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="message">The buffer to hold the decrypted message. The size must be cipher length - <see cref="MacSize"/>(16 bytes).</param>
    /// <returns><c>true</c> if decryption is successful; otherwise, <c>false</c>.</returns>
    public static bool TryDecrypt(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> nonce24, ReadOnlySpan<byte> secretKey32, ReadOnlySpan<byte> publicKey32, Span<byte> message)
    {
        if (cipher.Length < MacSize)
        {
            throw new ArgumentOutOfRangeException($"The {nameof(cipher)} length must be at least {MacSize} bytes.");
        }

        if (nonce24.Length != NonceSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(nonce24), NonceSize);
        }

        if (secretKey32.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey32), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (message.Length != (cipher.Length - MacSize))
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(message), cipher.Length - MacSize);
        }

        return LibsodiumInterops.crypto_box_open_easy(message, cipher, (ulong)cipher.Length, nonce24, publicKey32, secretKey32) == 0;
    }

    public static bool PublicKey_BoxToSign(ReadOnlySpan<byte> boxPublicKey32, Span<byte> signPublicKey32)
    {
        if (boxPublicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey32), PublicKeySize);
        }

        if (signPublicKey32.Length != CryptoSign.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey32), CryptoSign.PublicKeySize);
        }

        Ed25519Helper.fe25519_frombytes(out var x, boxPublicKey32);
        var one = new fe25519(1);
        Ed25519Helper.fe25519_sub(out var xMinusOne, ref x, ref one);
        Ed25519Helper.fe25519_add(out var xPlusOne, ref x, ref one);
        Ed25519Helper.fe25519_invert(out var inv, ref xPlusOne);
        Ed25519Helper.fe25519_mul(out var res, ref xMinusOne, ref inv);
        Ed25519Helper.fe25519_tobytes(signPublicKey32, ref res);

        return true;
    }
}
