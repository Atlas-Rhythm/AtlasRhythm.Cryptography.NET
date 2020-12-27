using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;

namespace AtlasRhythm.Cryptography.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Parameters
    {
        [TestMethod]
        public void Parameters_KeyNull()
        {
            void action() { using (var aead = new Chacha20Poly1305(null)) { } }

            var ex = Assert.ThrowsException<ArgumentNullException>(action);
            Assert.AreEqual("key", ex.ParamName);
        }

        [TestMethod]
        public void Parameters_KeyTooShort()
        {
            var key = new byte[Chacha20Poly1305.KeySize - 1];
            void action() { using (var aead = new Chacha20Poly1305(key)) { } }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "key");
            StringAssert.Contains(ex.Message.ToLower(), "size");
        }

        [TestMethod]
        public void Parameters_KeyTooLong()
        {
            var key = new byte[Chacha20Poly1305.KeySize + 1];
            void action() { using (var aead = new Chacha20Poly1305(key)) { } }

            var ex = Assert.ThrowsException<CryptographicException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "key");
            StringAssert.Contains(ex.Message.ToLower(), "size");
        }

        [TestMethod]
        public void Parameters_NonceNull()
        {
            var key = TestData.Key;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(null, plaintext, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentNullException>(action);
            Assert.AreEqual("nonce", ex.ParamName);
        }

        [TestMethod]
        public void Parameters_PlaintextNull()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[0];
            var tag = new byte[Chacha20Poly1305.TagSize];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, null, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentNullException>(action);
            Assert.AreEqual("plaintext", ex.ParamName);
        }

        [TestMethod]
        public void Parameters_CiphertextNull()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var tag = new byte[Chacha20Poly1305.TagSize];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, null, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentNullException>(action);
            Assert.AreEqual("ciphertext", ex.ParamName);
        }

        [TestMethod]
        public void Parameters_TagNull()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, ciphertext, null, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentNullException>(action);
            Assert.AreEqual("tag", ex.ParamName);
        }

        [TestMethod]
        public void Parameters_NonceTooShort()
        {
            var key = TestData.Key;
            var nonce = new byte[Chacha20Poly1305.NonceSize - 1];
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentException>(action);
            Assert.AreEqual("nonce", ex.ParamName);
            StringAssert.Contains(ex.Message.ToLower(), "size");
        }

        [TestMethod]
        public void Parameters_NonceTooLong()
        {
            var key = TestData.Key;
            var nonce = new byte[Chacha20Poly1305.NonceSize + 1];
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentException>(action);
            Assert.AreEqual("nonce", ex.ParamName);
            StringAssert.Contains(ex.Message.ToLower(), "size");
        }

        [TestMethod]
        public void Parameters_TagTooShort()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize - 1];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentException>(action);
            Assert.AreEqual("tag", ex.ParamName);
            StringAssert.Contains(ex.Message.ToLower(), "size");
        }

        [TestMethod]
        public void Parameters_TagTooLong()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize + 1];

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentException>(action);
            Assert.AreEqual("tag", ex.ParamName);
            StringAssert.Contains(ex.Message.ToLower(), "size");
        }

        [TestMethod]
        public void Parameters_MismatchedLengths()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = new byte[0];
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[1];
            var tag = TestData.Tag;

            void action()
            {
                using (var aead = new Chacha20Poly1305(key))
                    aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            var ex = Assert.ThrowsException<ArgumentException>(action);
            StringAssert.Contains(ex.Message.ToLower(), "plaintext");
            StringAssert.Contains(ex.Message.ToLower(), "ciphertext");
            StringAssert.Contains(ex.Message.ToLower(), "length");
        }
    }
}
