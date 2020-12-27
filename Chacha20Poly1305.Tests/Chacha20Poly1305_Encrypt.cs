using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlasRhythm.Cryptography.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Encrypt
    {
        [TestMethod]
        public void Encrypt_Exact()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using (var aead = new Chacha20Poly1305(key))
                aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreEqual(TestData.Tag, tag);
        }

        [TestMethod]
        public void Encrypt_DifferentKey()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            key[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using (var aead = new Chacha20Poly1305(key))
                aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreNotEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);
        }

        [TestMethod]
        public void Encrypt_DifferentNonce()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            nonce[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using (var aead = new Chacha20Poly1305(key))
                aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreNotEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);
        }

        [TestMethod]
        public void Encrypt_DifferentPlaintext()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            plaintext[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using (var aead = new Chacha20Poly1305(key))
                aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreNotEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);
        }

        [TestMethod]
        public void Encrypt_DifferentAssociatedData()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            associatedData[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using (var aead = new Chacha20Poly1305(key))
                aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);
        }

        [TestMethod]
        public void Encrypt_NoAssociatedData()
        {
            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using (var aead = new Chacha20Poly1305(key))
                aead.Encrypt(nonce, plaintext, ciphertext, tag);

            CollectionAssert.AreEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);
        }
    }
}
