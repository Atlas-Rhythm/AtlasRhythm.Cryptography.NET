// Copyright 2020 Atlas Rhythm
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Security.Cryptography;

namespace AtlasRhythm.Cryptography
{
    /// <summary>
    /// Represents a key to be used with ChaCha20 and Poly1305 for Authenticated Encryption with Associated Data.
    /// </summary>
    public sealed class Chacha20Poly1305 : IDisposable
    {
        /// <summary>
        /// Key size, in bytes, supported by this instance.
        /// </summary>
        public const int KeySize = Chacha20.KeySize;
        /// <summary>
        /// Nonce size, in bytes, supported by this instance.
        /// </summary>
        public const int NonceSize = Chacha20.NonceSize;
        /// <summary>
        /// Tag size, in bytes, supported by this instance.
        /// </summary>
        public const int TagSize = Poly1305.TagSize;

        /// <summary>
        /// Gets the key sizes, in bytes, supported by this instance.
        /// </summary>
        public static KeySizes KeyByteSizes { get; } = new KeySizes(KeySize, KeySize, 1);
        /// <summary>
        /// Gets the nonce sizes, in bytes, supported by this instance.
        /// </summary>
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 1);
        /// <summary>
        /// Gets the tag sizes, in bytes, supported by this instance.
        /// </summary>
        public static KeySizes TagByteSizes { get; } = new KeySizes(TagSize, TagSize, 1);

#if DEBUG
        public const string NoSse2Var = "NO_SSE2";
        public const string NoAvx2Var = "NO_AVX2";
#endif

        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="Chacha20Poly1305"/> class with a provided key.
        /// </summary>
        /// <param name="key">The secret key to use for this instance.</param>
        /// <exception cref="ArgumentNullException">The `key` parameter is `null`.</exception>
        /// <exception cref="CryptographicException">The key parameter length is other than 32 bytes (256 bits).</exception>
        public Chacha20Poly1305(byte[] key)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            CheckKey(key);
            this.key = key;
        }

        /// <summary>
        /// Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a separate buffer.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
        /// <param name="tag">The byte array to receive the generated authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <exception cref="ArgumentNullException">The `nonce`, `plaintext`, `cyphertext`, or `tag` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `plaintext` parameter and the `ciphertext` do not have the same length.</exception>
        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = default)
        {
            CheckParameters(nonce, plaintext, ciphertext, tag);

            int size = ciphertext.Length;
            int associatedDataSize = associatedData is null ? 0 : associatedData.Length;

            unsafe
            {
                fixed (byte* k = key, n = nonce, p = plaintext, a = associatedData, c = ciphertext, t = tag)
                    Encrypt(k, n, p, size, a, associatedDataSize, c, t);
            }
        }

        /// <summary>
        /// Decrypts the ciphertext into the provided destination buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="tag">The authentication tag produced for this message during encryption.</param>
        /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <exception cref="ArgumentNullException">The `nonce`, `cyphertext`, `plaintext`, or `tag` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `ciphertext` parameter and the `plaintext` do not have the same length.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = default)
        {
            CheckParameters(nonce, plaintext, ciphertext, tag);

            int size = ciphertext.Length;
            int associatedDataSize = associatedData is null ? 0 : associatedData.Length;

            unsafe
            {
                fixed (byte* k = key, n = nonce, c = ciphertext, t = tag, a = associatedData, p = plaintext)
                    if (!Decrypt(k, n, c, size, t, a, associatedDataSize, p))
                        throw new CryptographicException("Computed and provided tags don't match.");
            }
        }

        /// <summary>
        /// Encrypts the plaintext and returns the concatenated ciphertext and authentication tag in a new buffer.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <returns>The byte array containing the concatenated ciphertext and authentication tag.</returns>
        /// <exception cref="ArgumentNullException">The `nonce` or `plaintext` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        public byte[] Encrypt(byte[] nonce, byte[] plaintext, byte[] associatedData = default)
        {
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];
            Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

            var ciphertextAndTag = new byte[ciphertext.Length + TagSize];
            Array.Copy(ciphertext, ciphertextAndTag, ciphertext.Length);
            Array.Copy(tag, 0, ciphertextAndTag, ciphertext.Length, TagSize);
            return ciphertextAndTag;
        }

        /// <summary>
        /// Decrypts the ciphertext and returns the plaintext in a new buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertextAndTag">The byte array containing the concatenated ciphertext and authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The byte array containing the plaintext.</returns>
        /// <exception cref="ArgumentNullException">The `nonce` or `cyphertext` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        public byte[] Decrypt(byte[] nonce, byte[] ciphertextAndTag, byte[] associatedData = default)
        {
            var ciphertext = new byte[ciphertextAndTag.Length - TagSize];
            var tag = new byte[TagSize];
            Array.Copy(ciphertextAndTag, ciphertext, ciphertext.Length);
            Array.Copy(ciphertextAndTag, ciphertext.Length, tag, 0, TagSize);

            var plaintext = new byte[ciphertext.Length];
            Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return plaintext;
        }

        private static unsafe void Encrypt(
            byte* key,
            byte* nonce,
            byte* plaintext,
            int size,
            byte* associatedData,
            int associatedDataSize,
            byte* ciphertext,
            byte* tag)
        {
            int i;
            uint* chacha20State = stackalloc uint[Chacha20.StateSize];

            for (i = 0; i < size; ++i) ciphertext[i] = plaintext[i];
            Chacha20.State(chacha20State, key, 1, nonce);
            Chacha20.Cipher(chacha20State, ciphertext, size);

            chacha20State[12] = 0;
            Tag(ciphertext, size, associatedData, associatedDataSize, chacha20State, tag);

            for (i = 4; i < Chacha20.StateSize; ++i) chacha20State[i] = 0;
        }

        private static unsafe bool Decrypt(
            byte* key,
            byte* nonce,
            byte* ciphertext,
            int size,
            byte* tag,
            byte* associatedData,
            int associatedDataSize,
            byte* plaintext)
        {
            int i;
            uint* chacha20State = stackalloc uint[Chacha20.StateSize];
            byte* computedTag = stackalloc byte[Poly1305.TagSize];

            Chacha20.State(chacha20State, key, 0, nonce);
            Tag(ciphertext, size, associatedData, associatedDataSize, chacha20State, computedTag);
            bool valid = Poly1305.Verify(tag, computedTag);

            if (valid)
            {
                for (i = 0; i < size; ++i) plaintext[i] = ciphertext[i];
                chacha20State[12] = 1;
                Chacha20.Cipher(chacha20State, plaintext, size);
            }

            for (i = 4; i < Chacha20.StateSize; ++i) chacha20State[i] = 0;
            for (i = 0; i < Poly1305.TagSize; ++i) computedTag[i] = 0;

            return valid;
        }

        private static unsafe void Tag(
            byte* ciphertext,
            int ciphertextSize,
            byte* associatedData,
            int associatedDataSize,
            uint* chacha20State,
            byte* tag)
        {
            int i;
            byte* poly1305key = stackalloc byte[Poly1305.KeySize];
            byte* padding = stackalloc byte[Poly1305.BlockSize - 1];
            byte* u64 = stackalloc byte[sizeof(ulong)];

            Chacha20.Cipher(chacha20State, poly1305key, Poly1305.KeySize);

            int padding1 = Poly1305.BlockSize - (associatedDataSize % Poly1305.BlockSize);
            int padding2 = Poly1305.BlockSize - (ciphertextSize % Poly1305.BlockSize);

            Poly1305.State poly1305State;
            Poly1305.Init(&poly1305State, poly1305key);

            Poly1305.Update(&poly1305State, associatedData, associatedDataSize);
            Poly1305.Update(&poly1305State, padding, padding1);

            Poly1305.Update(&poly1305State, ciphertext, ciphertextSize);
            Poly1305.Update(&poly1305State, padding, padding2);

            Memory.U64ToU8((ulong)associatedDataSize, u64);
            Poly1305.Update(&poly1305State, u64, sizeof(ulong));

            Memory.U64ToU8((ulong)ciphertextSize, u64);
            Poly1305.Update(&poly1305State, u64, sizeof(ulong));

            Poly1305.Finish(&poly1305State, tag);

            for (i = 0; i < Poly1305.KeySize; ++i) poly1305key[i] = 0;
        }

        private static void CheckKey(byte[] key)
        {
            if (key.Length != KeySize)
                throw new CryptographicException("Specified key is not a valid size for this algorithm.");
        }

        private static void CheckParameters(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag)
        {
            if (nonce is null) throw new ArgumentNullException(nameof(nonce));
            if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));
            if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
            if (tag is null) throw new ArgumentNullException(nameof(tag));

            if (nonce.Length != NonceSize)
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (tag.Length != TagSize)
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));

            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException("Plaintext and ciphertext must have the same length.");
        }

        public void Dispose()
        {
            for (int i = 0; i < KeySize; ++i) key[i] = 0;
        }
    }
}
