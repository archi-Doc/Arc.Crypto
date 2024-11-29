// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

namespace Arc.Crypto;

/// <summary>
/// A low-level helper class for calling crypto_sign function in Libsodium, which implements public-key signature algorithm.<br/>
/// Seed 32 bytes, Secret key 64bytes, Public key 32bytes, Signature 64 bytes.<br/>
/// Single-part signature: Ed25519, Multi-part signature: Ed25519ph.
/// </summary>
public static class CryptoSign
{
    /// <summary>
    /// The size of the seed in bytes.
    /// </summary>
    public const int SeedSize = 32;

    /// <summary>
    /// The size of the secret key in bytes.
    /// </summary>
    public const int SecretKeySize = 64;

    /// <summary>
    /// The size of the public key in bytes.
    /// </summary>
    public const int PublicKeySize = 32;

    /// <summary>
    /// The size of the signature in bytes.
    /// </summary>
    public const int SignatureSize = 64;

    /// <summary>
    /// Creates a new key pair (secret(64) and public key(32)).
    /// </summary>
    /// <param name="secretKey64">A span to hold the secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="publicKey32">A span to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void CreateKey(Span<byte> secretKey64, Span<byte> publicKey32)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_keypair(publicKey32, secretKey64);
    }

    /// <summary>
    /// Creates a new key pair (secret(64) and public(32) key) from a seed(32).
    /// </summary>
    /// <param name="seed32">The seed span. The size must be <see cref="SeedSize"/>(32 bytes).</param>
    /// <param name="secretKey64">A span to hold the secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="publicKey32">A span to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void CreateKey(ReadOnlySpan<byte> seed32, Span<byte> secretKey64, Span<byte> publicKey32)
    {
        if (seed32.Length != SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed32), SeedSize);
        }

        if (secretKey64.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_seed_keypair(publicKey32, secretKey64, seed32);
    }

    /// <summary>
    /// Extracts the seed(32) from a secret key(64).
    /// </summary>
    /// <param name="secretKey64">The secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="seed32">A span to hold the seed. The size must be <see cref="SeedSize"/>(32 bytes).</param>
    public static void SecretKeyToSeed(ReadOnlySpan<byte> secretKey64, Span<byte> seed32)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (seed32.Length < SeedSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(seed32), SeedSize);
        }

        secretKey64.Slice(0, SeedSize).CopyTo(seed32); // LibsodiumInterops.crypto_sign_ed25519_sk_to_seed(seed, secretKey);
    }

    /// <summary>
    /// Extracts the public key(32) from a secret key(64).
    /// </summary>
    /// <param name="secretKey64">The secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="publicKey32">A span to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    public static void SecretKeyToPublicKey(ReadOnlySpan<byte> secretKey64, Span<byte> publicKey32)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (publicKey32.Length < PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        secretKey64.Slice(SeedSize, PublicKeySize).CopyTo(publicKey32); // LibsodiumInterops.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
    }

    /// <summary>
    /// Signs a message using a secret key(64).
    /// </summary>
    /// <param name="message">The message to be signed.</param>
    /// <param name="secretKey64">The secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="signature64">A span to hold the signature. The size must be <see cref="SignatureSize"/>(64 bytes).</param>
    public static void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey64, Span<byte> signature64)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (signature64.Length != SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature64), SignatureSize);
        }

        LibsodiumInterops.crypto_sign_ed25519_detached(signature64, out var signatureLength, message, (ulong)message.Length, secretKey64);
    }

    /// <summary>
    /// Verifies a message signature using a public key(32).
    /// </summary>
    /// <param name="message">The message span to be verified.</param>
    /// <param name="publicKey32">The public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="signature64">The signature. The size must be <see cref="SignatureSize"/>(64 bytes).</param>
    /// <returns>True if the signature is valid; otherwise, false.</returns>
    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey32, ReadOnlySpan<byte> signature64)
    {
        if (publicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (signature64.Length != SignatureSize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signature64), SignatureSize);
        }

        return LibsodiumInterops.crypto_sign_ed25519_verify_detached(signature64, message, (ulong)message.Length, publicKey32) == 0;
    }
}
