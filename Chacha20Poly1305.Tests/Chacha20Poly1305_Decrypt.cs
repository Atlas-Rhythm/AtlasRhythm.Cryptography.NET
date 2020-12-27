using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace AtlasRhythm.Cryptography.Tests
{
    [TestClass]
    public class Chacha20Poly1305_Decrypt
    {
        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_Exact(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = TestData.Key;
            var nonce = TestData.Nonce;
            var ciphertext = TestData.Ciphertext;
            var tag = TestData.Tag;
            var associatedData = TestData.AssociatedData;

            var plaintext = new byte[ciphertext.Length];

            using var aead = new Chacha20Poly1305(key);
            aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            CollectionAssert.AreEqual(TestData.Plaintext, plaintext);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_DifferentKey(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

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

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_DifferentNonce(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

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

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_DifferentCiphertext(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

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

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_DifferentTag(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

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

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_DifferentAssociatedData(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

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

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_NoAssociatedData(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

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

            TestHelpers.ClearEnv();
        }
    }
}
