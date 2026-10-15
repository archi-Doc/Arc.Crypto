// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System.Security.Cryptography;

namespace Arc.Crypto;

/// <summary>
/// Low-level wrapper for the Libsodium Ed25519 signature functions (crypto_sign).<br/>
/// Seed 32 bytes, secret key 64 bytes (seed followed by public key), public key 32 bytes, signature 64 bytes.<br/>
/// For multi-part (prehashed) signatures, use <see cref="Ed25519ph"/>; its signatures are not compatible with <see cref="Verify"/>.
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
    /// Creates a random key pair (secret key 64 bytes, public key 32 bytes).
    /// </summary>
    /// <param name="secretKey64">A span to hold the secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="publicKey32">A span to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid.</exception>
    public static void CreateKeyPair(Span<byte> secretKey64, Span<byte> publicKey32)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        LibsodiumInterops.crypto_sign_keypair(publicKey32, secretKey64);
    }

    /// <summary>
    /// Creates a deterministic key pair (secret key 64 bytes, public key 32 bytes) from a 32-byte seed.<br/>
    /// The seed may overlap the outputs.
    /// </summary>
    /// <param name="seed32">The seed span. The size must be <see cref="SeedSize"/>(32 bytes).</param>
    /// <param name="secretKey64">A span to hold the secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="publicKey32">A span to hold the public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid.</exception>
    public static void CreateKeyPair(ReadOnlySpan<byte> seed32, Span<byte> secretKey64, Span<byte> publicKey32)
    {
        if (seed32.Length != SeedSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(seed32), SeedSize);
        }

        if (secretKey64.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (seed32.Overlaps(secretKey64) || seed32.Overlaps(publicKey32))
        {// Libsodium copies the seed into the secret key after writing both keys (e.g. seed32 = secretKey64[..32]), so work from a copy.
            Span<byte> copy = stackalloc byte[SeedSize];
            try
            {
                seed32.CopyTo(copy);
                LibsodiumInterops.crypto_sign_seed_keypair(publicKey32, secretKey64, copy);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(copy);
            }

            return;
        }

        LibsodiumInterops.crypto_sign_seed_keypair(publicKey32, secretKey64, seed32);
    }

    /// <summary>
    /// Extracts the seed(32) from a secret key(64).
    /// </summary>
    /// <param name="secretKey64">The secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="seed32">A buffer of at least <see cref="SeedSize"/> (32) bytes. Trailing bytes are unchanged.</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid.</exception>
    public static void SecretKeyToSeed(ReadOnlySpan<byte> secretKey64, Span<byte> seed32)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (seed32.Length < SeedSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(seed32), SeedSize);
        }

        secretKey64.Slice(0, SeedSize).CopyTo(seed32); // LibsodiumInterops.crypto_sign_ed25519_sk_to_seed(seed, secretKey);
    }

    /// <summary>
    /// Extracts the public key(32) from a secret key(64).
    /// </summary>
    /// <param name="secretKey64">The secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="publicKey32">A buffer of at least <see cref="PublicKeySize"/> (32) bytes. Trailing bytes are unchanged.</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid.</exception>
    public static void SecretKeyToPublicKey(ReadOnlySpan<byte> secretKey64, Span<byte> publicKey32)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (publicKey32.Length < PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        secretKey64.Slice(SeedSize, PublicKeySize).CopyTo(publicKey32); // LibsodiumInterops.crypto_sign_ed25519_sk_to_pk(publicKey, secretKey);
    }

    /// <summary>
    /// Signs a message using a secret key(64).
    /// </summary>
    /// <param name="message">The message to be signed.</param>
    /// <param name="secretKey64">The secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="signature64">A span to hold the signature. The size must be <see cref="SignatureSize"/>(64 bytes).<br/>
    /// It may overlap <paramref name="message"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid.</exception>
    public static void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> secretKey64, Span<byte> signature64)
    {
        if (secretKey64.Length != SecretKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(secretKey64), SecretKeySize);
        }

        if (signature64.Length != SignatureSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(signature64), SignatureSize);
        }

        if (message.Overlaps(signature64))
        {// Libsodium writes R and A into the signature before hashing the message a second time, so sign into a separate buffer.
            Span<byte> temp = stackalloc byte[SignatureSize];
            LibsodiumInterops.crypto_sign_ed25519_detached(temp, out _, message, (ulong)message.Length, secretKey64);
            temp.CopyTo(signature64);
            return;
        }

        LibsodiumInterops.crypto_sign_ed25519_detached(signature64, out var signatureLength, message, (ulong)message.Length, secretKey64);
    }

    /// <summary>
    /// Verifies a message signature using a public key(32).
    /// </summary>
    /// <param name="message">The message span to be verified.</param>
    /// <param name="publicKey32">The public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="signature64">The signature. The size must be <see cref="SignatureSize"/>(64 bytes).</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The size of a span is invalid.</exception>
    public static bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey32, ReadOnlySpan<byte> signature64)
    {
        if (publicKey32.Length != PublicKeySize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(publicKey32), PublicKeySize);
        }

        if (signature64.Length != SignatureSize)
        {
            BaseHelper.ThrowSizeMismatchException(nameof(signature64), SignatureSize);
        }

        return LibsodiumInterops.crypto_sign_ed25519_verify_detached(signature64, message, (ulong)message.Length, publicKey32) == 0;
    }
}
