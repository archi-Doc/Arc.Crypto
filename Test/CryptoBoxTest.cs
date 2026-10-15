// Copyright (c) All contributors. All rights reserved. Licensed under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography;
using Arc.Crypto;
using Xunit;

namespace Test;

public class CryptoBoxTest
{
    // RFC 7748, section 6.1 (Curve25519 test vector).
    private static readonly byte[] AliceSecretKey = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    private static readonly byte[] AlicePublicKey = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    private static readonly byte[] BobSecretKey = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    private static readonly byte[] BobPublicKey = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    private static readonly byte[] SharedSecret = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // libsodium test/default/box.c and box.exp (from "Cryptography in NaCl"): nonce, message (m[32..163]) and c[16..163],
    // which is MAC(16) followed by the encrypted message. test/default/secretbox.c uses the same nonce and message with firstkey.
    private static readonly byte[] Nonce = Convert.FromHexString("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
    private static readonly byte[] Message = Convert.FromHexString(
        "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705");

    private static readonly byte[] Ciphertext = Convert.FromHexString(
        "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5");

    private static readonly byte[] SecretBoxKey = Convert.FromHexString("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");

    [Fact]
    public void X25519KnownAnswers()
    {
        var basePoint = new byte[CryptoBox.PublicKeySize];
        basePoint[0] = 9;
        var output = new byte[CryptoBox.SharedSecretSize];

        CryptoBox.DeriveSharedSecret(AliceSecretKey, basePoint, output);
        output.Is(AlicePublicKey);
        CryptoBox.DeriveSharedSecret(BobSecretKey, basePoint, output);
        output.Is(BobPublicKey);
        CryptoBox.DeriveSharedSecret(AliceSecretKey, BobPublicKey, output);
        output.Is(SharedSecret);
        CryptoBox.DeriveSharedSecret(BobSecretKey, AlicePublicKey, output);
        output.Is(SharedSecret);
    }

    [Fact]
    public void BoxKnownAnswer()
    {
        Message.Length.Is(131);
        Ciphertext.Length.Is(Message.Length + CryptoBox.MacSize);

        var ciphertext = new byte[Message.Length + CryptoBox.MacSize];
        CryptoBox.Encrypt(Message, Nonce, AliceSecretKey, BobPublicKey, ciphertext);
        ciphertext.Is(Ciphertext);

        var plaintext = new byte[Message.Length];
        CryptoBox.TryDecrypt(Ciphertext, Nonce, BobSecretKey, AlicePublicKey, plaintext).IsTrue();
        plaintext.Is(Message);

        // X25519(a, B) = X25519(b, A), so the sender's secret key with the recipient's public key opens it too.
        CryptoBox.TryDecrypt(Ciphertext, Nonce, AliceSecretKey, BobPublicKey, plaintext).IsTrue();
        plaintext.Is(Message);
    }

    [Fact]
    public void SecretBoxKnownAnswer()
    {
        var ciphertext = new byte[Message.Length + CryptoSecretBox.MacSize];
        CryptoSecretBox.Encrypt(Message, Nonce, SecretBoxKey, ciphertext);
        ciphertext.Is(Ciphertext);

        var plaintext = new byte[Message.Length];
        CryptoSecretBox.TryDecrypt(Ciphertext, Nonce, SecretBoxKey, plaintext).IsTrue();
        plaintext.Is(Message);
    }

    [Fact]
    public void LayoutIsMacFollowedByEncryptedMessage()
    {
        var c1 = new byte[Message.Length + CryptoBox.MacSize];
        var c2 = new byte[Message.Length + CryptoBox.MacSize];
        var modified = Message.ToArray();
        modified[5] ^= 1;
        CryptoBox.Encrypt(Message, Nonce, AliceSecretKey, BobPublicKey, c1);
        CryptoBox.Encrypt(modified, Nonce, AliceSecretKey, BobPublicKey, c2);

        // A stream cipher: flipping message byte i flips ciphertext byte MacSize + i, and changes the MAC at the front.
        for (var i = 0; i < Message.Length; i++)
        {
            (c1[CryptoBox.MacSize + i] ^ c2[CryptoBox.MacSize + i]).Is(i == 5 ? 1 : 0);
        }

        c1.AsSpan(0, CryptoBox.MacSize).SequenceEqual(c2.AsSpan(0, CryptoBox.MacSize)).IsFalse();

        var s1 = new byte[Message.Length + CryptoSecretBox.MacSize];
        var s2 = new byte[Message.Length + CryptoSecretBox.MacSize];
        CryptoSecretBox.Encrypt(Message, Nonce, SecretBoxKey, s1);
        CryptoSecretBox.Encrypt(modified, Nonce, SecretBoxKey, s2);
        for (var i = 0; i < Message.Length; i++)
        {
            (s1[CryptoSecretBox.MacSize + i] ^ s2[CryptoSecretBox.MacSize + i]).Is(i == 5 ? 1 : 0);
        }

        s1.AsSpan(0, CryptoSecretBox.MacSize).SequenceEqual(s2.AsSpan(0, CryptoSecretBox.MacSize)).IsFalse();
    }

    [Fact]
    public void EmptyMessageAndTampering()
    {
        var mac = new byte[CryptoBox.MacSize];
        CryptoBox.Encrypt(ReadOnlySpan<byte>.Empty, Nonce, AliceSecretKey, BobPublicKey, mac);
        CryptoBox.TryDecrypt(mac, Nonce, BobSecretKey, AlicePublicKey, Span<byte>.Empty).IsTrue();
        mac[0] ^= 1;
        CryptoBox.TryDecrypt(mac, Nonce, BobSecretKey, AlicePublicKey, Span<byte>.Empty).IsFalse();

        CryptoSecretBox.Encrypt(ReadOnlySpan<byte>.Empty, Nonce, SecretBoxKey, mac);
        CryptoSecretBox.TryDecrypt(mac, Nonce, SecretBoxKey, Span<byte>.Empty).IsTrue();
        mac[15] ^= 0x80;
        CryptoSecretBox.TryDecrypt(mac, Nonce, SecretBoxKey, Span<byte>.Empty).IsFalse();

        var plaintext = new byte[Message.Length];
        foreach (var index in new[] { 0, CryptoBox.MacSize - 1, CryptoBox.MacSize, Ciphertext.Length - 1 })
        {
            var tampered = Ciphertext.ToArray();
            tampered[index] ^= 1;
            CryptoBox.TryDecrypt(tampered, Nonce, BobSecretKey, AlicePublicKey, plaintext).IsFalse();
            CryptoSecretBox.TryDecrypt(tampered, Nonce, SecretBoxKey, plaintext).IsFalse();
        }

        // Wrong nonce, wrong recipient key, wrong sender key.
        var wrongNonce = Nonce.ToArray();
        wrongNonce[23] ^= 1;
        CryptoBox.TryDecrypt(Ciphertext, wrongNonce, BobSecretKey, AlicePublicKey, plaintext).IsFalse();
        var wrongKey = BobSecretKey.ToArray();
        wrongKey[1]++;
        CryptoBox.TryDecrypt(Ciphertext, Nonce, wrongKey, AlicePublicKey, plaintext).IsFalse();
        CryptoBox.TryDecrypt(Ciphertext, Nonce, BobSecretKey, BobPublicKey, plaintext).IsFalse();

        // A low-order (all-zero) sender public key is rejected rather than authenticated.
        CryptoBox.TryDecrypt(Ciphertext, Nonce, BobSecretKey, new byte[CryptoBox.PublicKeySize], plaintext).IsFalse();
    }

    [Fact]
    public void SeedKeyPairDerivation()
    {
        var random = new Xoshiro256StarStar(20);
        var seed = new byte[CryptoBox.SeedSize];
        var secretKey = new byte[CryptoBox.SecretKeySize];
        var publicKey = new byte[CryptoBox.PublicKeySize];
        var basePoint = new byte[CryptoBox.PublicKeySize];
        basePoint[0] = 9;
        var derived = new byte[CryptoBox.PublicKeySize];
        for (var i = 0; i < 16; i++)
        {
            random.NextBytes(seed);
            CryptoBox.CreateKeyPair(seed, secretKey, publicKey);

            // crypto_box_seed_keypair: sk = SHA-512(seed)[0..32], pk = X25519(sk, 9).
            secretKey.Is(SHA512.HashData(seed).AsSpan(0, CryptoBox.SecretKeySize).ToArray());
            CryptoBox.DeriveSharedSecret(secretKey, basePoint, derived);
            derived.Is(publicKey);
        }
    }
}
