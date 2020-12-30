using AtlasRhythm.Cryptography.Aeads;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace AtlasRhythm.Cryptography.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Roundtrip
    {
        [TestMethod]
        public void Roundtrip()
        {
            var key = new byte[Chacha20Poly1305.KeySize];
            var nonce = new byte[Chacha20Poly1305.NonceSize];
            var plaintext = new byte[1234];
            var associatedData = new byte[56];

            var rng = new Random(2112);
            rng.NextBytes(key);
            rng.NextBytes(nonce);
            rng.NextBytes(plaintext);
            rng.NextBytes(associatedData);

            using var aead = new Chacha20Poly1305(key);

            var simdOutput = aead.Encrypt(nonce, plaintext, associatedData);
            TestHelpers.SetEnv(false, false);
            var noSimdOutput = aead.Encrypt(nonce, plaintext, associatedData);
            TestHelpers.ClearEnv();

            CollectionAssert.AreEqual(simdOutput, noSimdOutput);

            var simdPlaintext = aead.Decrypt(nonce, simdOutput, associatedData);
            TestHelpers.SetEnv(false, false);
            var noSimdPlaintext = aead.Decrypt(nonce, noSimdOutput, associatedData);
            TestHelpers.ClearEnv();

            CollectionAssert.AreEqual(plaintext, simdPlaintext);
            CollectionAssert.AreEqual(plaintext, noSimdPlaintext);
        }

        [TestMethod]
        public void Roundtrip_NoAssociatedData()
        {
            var key = new byte[Chacha20Poly1305.KeySize];
            var nonce = new byte[Chacha20Poly1305.NonceSize];
            var plaintext = new byte[1234];

            var rng = new Random(2112);
            rng.NextBytes(key);
            rng.NextBytes(nonce);
            rng.NextBytes(plaintext);

            using var aead = new Chacha20Poly1305(key);

            var simdOutput = aead.Encrypt(nonce, plaintext);
            TestHelpers.SetEnv(false, false);
            var noSimdOutput = aead.Encrypt(nonce, plaintext);
            TestHelpers.ClearEnv();

            CollectionAssert.AreEqual(simdOutput, noSimdOutput);

            var simdPlaintext = aead.Decrypt(nonce, simdOutput);
            TestHelpers.SetEnv(false, false);
            var noSimdPlaintext = aead.Decrypt(nonce, noSimdOutput);
            TestHelpers.ClearEnv();

            CollectionAssert.AreEqual(plaintext, simdPlaintext);
            CollectionAssert.AreEqual(plaintext, noSimdPlaintext);
        }
    }
}
