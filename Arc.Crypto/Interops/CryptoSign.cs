// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using Arc.Crypto.Ed25519;

namespace Arc.Crypto;

/// <summary>
/// Helper class for calling crypto_sign function in Libsodium, which implements public-key signature algorithm.<br/>
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
    /// Creates a new key pair (secret and public key).
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
    /// Creates a new key pair (secret and public key) from a seed.
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

    public static void CreateKey2(ReadOnlySpan<byte> seed32, Span<byte> secretKey64, Span<byte> publicKey32)
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

        Sha2Helper.Get512_Span(seed32, secretKey64);
        secretKey64[0] &= 248; // 1111_1000
        secretKey64[31] &= 127; // 0111_1111
        secretKey64[31] |= 64; // 0100_0000

        ge25519_p3 A;
        Ed25519Helper.ge25519_scalarmult_base(out A, secretKey64);
        Ed25519Helper.ge25519_p3_tobytes(publicKey32, ref A);

        seed32.CopyTo(secretKey64);
        publicKey32.CopyTo(secretKey64.Slice(SeedSize));
    }

    /// <summary>
    /// Extracts the seed from a secret key.
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
    /// Extracts the public key from a secret key.
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
    /// Converts a signature secret key to a encryption secret key.
    /// </summary>
    /// <param name="signSecretKey64">The signature secret key. The size must be <see cref="SecretKeySize"/>(64 bytes).</param>
    /// <param name="boxSecretKey32">A span to hold the encryption secret key. The size must be <see cref="CryptoBox.SecretKeySize"/>(32 bytes).</param>
    public static void SecretKey_SignToBox(ReadOnlySpan<byte> signSecretKey64, Span<byte> boxSecretKey32)
    {
        if (signSecretKey64.Length != SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signSecretKey64), SecretKeySize);
        }

        if (boxSecretKey32.Length != CryptoBox.SecretKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxSecretKey32), SecretKeySize);
        }

        // LibsodiumInterops.crypto_sign_ed25519_sk_to_curve25519(boxSecretKey, signSecretKey);
        Span<byte> hash = stackalloc byte[64];
        LibsodiumInterops.crypto_hash(hash, signSecretKey64.Slice(0, 32), 32); // Sha2Helper.Get512_Span(signSecretKey.Slice(0, 32), hash);
        hash.Slice(0, 32).CopyTo(boxSecretKey32);
    }

    /// <summary>
    /// Converts a signature public key to an encryption public key.
    /// </summary>
    /// <param name="signPublicKey32">The signature public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="boxPublicKey32">A span to hold the encryption public key. The size must be <see cref="CryptoBox.PublicKeySize"/>(32 bytes).</param>
    /// <returns>True if the conversion is successful; otherwise, false.</returns>
    public static bool PublicKey_SignToBox(ReadOnlySpan<byte> signPublicKey32, Span<byte> boxPublicKey32)
    {
        if (signPublicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey32), PublicKeySize);
        }

        if (boxPublicKey32.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey32), CryptoBox.PublicKeySize);
        }

        return LibsodiumInterops.crypto_sign_ed25519_pk_to_curve25519(boxPublicKey32, signPublicKey32) == 0;
    }

    /// <summary>
    /// Converts a signature public key to an encryption public key.
    /// </summary>
    /// <param name="signPublicKey32">The signature public key. The size must be <see cref="PublicKeySize"/>(32 bytes).</param>
    /// <param name="boxPublicKey32">A span to hold the encryption public key. The size must be <see cref="CryptoBox.PublicKeySize"/>(32 bytes).</param>
    /// <returns>True if the conversion is successful; otherwise, false.</returns>
    public static bool PublicKey_SignToBox2(ReadOnlySpan<byte> signPublicKey32, Span<byte> boxPublicKey32)
    {
        if (signPublicKey32.Length != PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(signPublicKey32), PublicKeySize);
        }

        if (boxPublicKey32.Length != CryptoBox.PublicKeySize)
        {
            CryptoHelper.ThrowSizeMismatchException(nameof(boxPublicKey32), CryptoBox.PublicKeySize);
        }

        ge25519_p3 a;
        if (Ed25519Helper.ge25519_frombytes_negate_vartime(out a, signPublicKey32) != 0/* ||
            Ed25519Helper.ge25519_has_small_order(ref a) != 0 ||
            Ed25519Helper.ge25519_is_on_main_subgroup(ref a) == 0*/)
        {
            return false;
        }

        var one = new fe25519(1);
        Ed25519Helper.fe25519_sub(out var xMinusOne, ref one, ref a.Y);
        Ed25519Helper.fe25519_add(out var xPlusOne, ref one, ref a.Y);
        Ed25519Helper.fe25519_invert(out var inv, ref xMinusOne);
        Ed25519Helper.fe25519_mul(out var res, ref xPlusOne, ref inv);
        Ed25519Helper.fe25519_tobytes(boxPublicKey32, ref res);

        return true;
    }

    /// <summary>
    /// Signs a message using a secret key.
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
    /// Verifies a message signature using a public key.
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
