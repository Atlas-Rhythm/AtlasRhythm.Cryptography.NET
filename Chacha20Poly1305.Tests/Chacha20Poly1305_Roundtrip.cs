using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Chacha20Poly1305.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Roundtrip
    {
        [TestMethod]
        public void Roundtrip()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = new byte[2112];
            var associatedData = TestData.AssociatedData;

            var rng = new Random(2112);
            rng.NextBytes(plaintext);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];
            var computedPlaintext = new byte[ciphertext.Length];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            aead.Decrypt(nonce, ciphertext, tag, computedPlaintext, associatedData);

            CollectionAssert.AreEqual(plaintext, computedPlaintext);
        }

        [TestMethod]
        public void Roundtrip_NoAssociatedData()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = new byte[2112];

            var rng = new Random(2112);
            rng.NextBytes(plaintext);

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];
            var computedPlaintext = new byte[ciphertext.Length];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag);
            aead.Decrypt(nonce, ciphertext, tag, computedPlaintext);

            CollectionAssert.AreEqual(plaintext, computedPlaintext);
        }
    }
}
