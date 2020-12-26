using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;

namespace Chacha20Poly1305.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Decrypt
    {
        [TestMethod]
        public void Decrypt_Exact()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            var plaintext = new byte[ciphertext.Length];

            using var aead = new Chacha20Poly1305(key);
            aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            CollectionAssert.AreEqual(TestData.Plaintext, plaintext);
        }

        [TestMethod]
        public void Decrypt_DifferentKey()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            key[0] = 0;

            var plaintext = new byte[ciphertext.Length];

            void action()
            {
                using var aead = new Chacha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "tag");
        }

        [TestMethod]
        public void Decrypt_DifferentNonce()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            nonce[0] = 0;

            var plaintext = new byte[ciphertext.Length];

            void action()
            {
                using var aead = new Chacha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "tag");
        }

        [TestMethod]
        public void Decrypt_DifferentCiphertext()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            ciphertext[0] = 0;

            var plaintext = new byte[ciphertext.Length];

            void action()
            {
                using var aead = new Chacha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "tag");
        }

        [TestMethod]
        public void Decrypt_DifferentTag()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            tag[0] = 0;

            var plaintext = new byte[ciphertext.Length];

            void action()
            {
                using var aead = new Chacha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "tag");
        }

        [TestMethod]
        public void Decrypt_DifferentAssociatedData()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            associatedData[0] = 0;

            var plaintext = new byte[ciphertext.Length];

            void action()
            {
                using var aead = new Chacha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "tag");
        }

        [TestMethod]
        public void Decrypt_NoAssociatedData()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;

            var plaintext = new byte[ciphertext.Length];

            void action()
            {
                using var aead = new Chacha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "tag");
        }
    }
}
