using AtlasRhythm.Cryptography.Aeads;
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

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;
            var associatedData = Chacha20Poly1305_TestData.AssociatedData;

            var plaintext = new byte[ciphertext.Length];

            using var aead = new Chacha20Poly1305(key);
            aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

            CollectionAssert.AreEqual(Chacha20Poly1305_TestData.Plaintext, plaintext);

            TestHelpers.ClearEnv();
        }

        [DataTestMethod]
        [DataRow(true, true)]
        [DataRow(true, false)]
        [DataRow(false, false)]
        public void Decrypt_DifferentKey(bool sse2, bool avx2)
        {
            TestHelpers.SetEnv(sse2, avx2);

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;
            var associatedData = Chacha20Poly1305_TestData.AssociatedData;

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

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;
            var associatedData = Chacha20Poly1305_TestData.AssociatedData;

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

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;
            var associatedData = Chacha20Poly1305_TestData.AssociatedData;

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

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;
            var associatedData = Chacha20Poly1305_TestData.AssociatedData;

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

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;
            var associatedData = Chacha20Poly1305_TestData.AssociatedData;

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

            var key = Chacha20Poly1305_TestData.Key;
            var nonce = Chacha20Poly1305_TestData.Nonce;
            var ciphertext = Chacha20Poly1305_TestData.Ciphertext;
            var tag = Chacha20Poly1305_TestData.Tag;

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
