using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace AtlasRhythm.Cryptography.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Encrypt
    {
        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Encrypt_Exact(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreEqual(TestData.Tag, tag);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Encrypt_DifferentKey(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            key[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreNotEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Encrypt_DifferentNonce(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            nonce[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreNotEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Encrypt_DifferentPlaintext(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            plaintext[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreNotEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Encrypt_DifferentAssociatedData(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;
            var associatedData = TestData.AssociatedData;

            associatedData[0] = 0;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            CollectionAssert.AreEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Encrypt_NoAssociatedData(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var plaintext = TestData.Plaintext;

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[Chacha20Poly1305.TagSize];

            using var aead = new Chacha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext, tag);

            CollectionAssert.AreEqual(TestData.Ciphertext, ciphertext);
            CollectionAssert.AreNotEqual(TestData.Tag, tag);

            TestHelpers.ClearEnv();
        }
    }
}
