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
            var plaintext = new byte[1024];
            var associatedData = new byte[12];

            var rng = new Random(2112);
            rng.NextBytes(key);
            rng.NextBytes(nonce);
            rng.NextBytes(plaintext);
            rng.NextBytes(associatedData);

            using var aead = new Chacha20Poly1305(key);
            var output = aead.Encrypt(nonce, plaintext, associatedData);
            var newPlaintext = aead.Decrypt(nonce, output, associatedData);

            CollectionAssert.AreEqual(plaintext, newPlaintext);
        }

        [TestMethod]
        public void Roundtrip_NoAssociatedData()
        {
            var key = new byte[Chacha20Poly1305.KeySize];
            var nonce = new byte[Chacha20Poly1305.NonceSize];
            var plaintext = new byte[1024];

            var rng = new Random(2112);
            rng.NextBytes(key);
            rng.NextBytes(nonce);
            rng.NextBytes(plaintext);

            using var aead = new Chacha20Poly1305(key);
            var output = aead.Encrypt(nonce, plaintext);
            var newPlaintext = aead.Decrypt(nonce, output);

            CollectionAssert.AreEqual(plaintext, newPlaintext);
        }
    }
}
