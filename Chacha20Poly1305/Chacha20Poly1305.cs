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
using System.Collections;
using System.Security.Cryptography;

namespace Chacha20Poly1305
{
    /// <summary>
    /// Represents a key to be used with ChaCha20 and Poly1305 for Authenticated Encryption with Associated Data.
    /// </summary>
    public sealed class Chacha20Poly1305
    {
        private const int KeySize = Chacha20.KeySize;
        private const int NonceSize = Chacha20.NonceSize;
        private const int TagSize = Poly1305.TagSize;

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

        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="Chacha20Poly1305"/> class with a provided key.
        /// </summary>
        /// <param name="key">The secret key to use for this instance.</param>
        /// <exception cref="ArgumentNullException">The `key` parameter is `null`.</exception>
        /// <exception cref="CryptographicException">The key parameter length is other than 32 bytes (256 bits).</exception>
        public Chacha20Poly1305(byte[] key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }
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
        /// <exception cref="ArgumentException">The `plaintext` parameter and the `ciphertext` do not have the same length.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = default)
        {
            if (associatedData is null)
            {
                associatedData = new byte[0];
            }
            CheckParameters(nonce, plaintext, ciphertext, tag);

            Array.Copy(plaintext, ciphertext, plaintext.Length);
            Chacha20.Cipher(key, 1, nonce, ciphertext);

            var poly1305Message = Poly1305MessageGen(associatedData, ciphertext);
            var poly1305Key = Poly1305KeyGen(key, nonce);
            Poly1305.Mac(poly1305Message, poly1305Key, tag);
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

            var output = new byte[ciphertext.Length + TagSize];
            Array.Copy(ciphertext, output, ciphertext.Length);
            Array.Copy(tag, 0, output, ciphertext.Length, TagSize);
            return output;
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
        /// <exception cref="ArgumentException">The `ciphertext` parameter and the `plaintext` do not have the same length.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = default)
        {
            if (associatedData is null)
            {
                associatedData = new byte[0];
            }
            CheckParameters(nonce, plaintext, ciphertext, tag);

            var poly1305Message = Poly1305MessageGen(associatedData, ciphertext);
            var poly1305Key = Poly1305KeyGen(key, nonce);
            var computedTag = new byte[TagSize];
            Poly1305.Mac(poly1305Message, poly1305Key, computedTag);
            if (!((IStructuralEquatable)computedTag).Equals(tag, StructuralComparisons.StructuralEqualityComparer))
            {
                throw new CryptographicException("Computed and provided tags do not match.");
            }

            Array.Copy(ciphertext, plaintext, ciphertext.Length);
            Chacha20.Cipher(key, 1, nonce, plaintext);
        }

        /// <summary>
        /// Decrypts the ciphertext and returns the plaintext in a new buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The byte array containing the concatenated ciphertext and authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The byte array containing the plaintext.</returns>
        /// <exception cref="ArgumentNullException">The `nonce` or `cyphertext` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        public byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] associatedData = default)
        {
            var actualCiphertext = new byte[ciphertext.Length - TagSize];
            var tag = new byte[TagSize];
            Array.Copy(ciphertext, actualCiphertext, actualCiphertext.Length);
            Array.Copy(ciphertext, actualCiphertext.Length, tag, 0, TagSize);

            var plaintext = new byte[actualCiphertext.Length];
            Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return plaintext;
        }

        private static byte[] Poly1305KeyGen(byte[] key, byte[] nonce)
        {
            var block = Chacha20.Block(key, 0, nonce);
            var poly1305Key = new byte[Poly1305.KeySize];
            Array.Copy(block, poly1305Key, Poly1305.KeySize);
            return poly1305Key;
        }

        private static byte[] Poly1305MessageGen(byte[] associatedData, byte[] ciphertext)
        {
            var padding1 = associatedData.Length % 16;
            var padding2 = ciphertext.Length % 16;

            var associatedDataStart = 0;
            var ciphertextStart = associatedDataStart + associatedData.Length + padding1;
            var additionalDataLengthStart = ciphertextStart + ciphertext.Length + padding2;
            var ciphertextLengthStart = additionalDataLengthStart + sizeof(ulong);

            var poly1305Message = new byte[ciphertextLengthStart + sizeof(ulong)];

            Array.Copy(associatedData, 0, poly1305Message, associatedDataStart, associatedData.Length);
            Array.Copy(ciphertext, 0, poly1305Message, ciphertextStart, ciphertext.Length);
            Array.Copy(LittleEndianBitConverter.GetBytes((ulong) associatedData.Length), 0, poly1305Message, additionalDataLengthStart, sizeof(ulong));
            Array.Copy(LittleEndianBitConverter.GetBytes((ulong) ciphertext.Length), 0, poly1305Message, ciphertextLengthStart, sizeof(ulong));

            return poly1305Message;
        }

        private static void CheckKey(byte[] key)
        {
            if (key.Length != KeySize)
            {
                throw new CryptographicException("Specified key is not a valid size for this algorithm.");
            }
        }

        private static void CheckParameters(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag)
        {
            if (nonce is null)
            {
                throw new ArgumentNullException(nameof(nonce));
            }
            if (plaintext is null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }
            if (ciphertext is null)
            {
                throw new ArgumentNullException(nameof(ciphertext));
            }
            if (tag is null)
            {
                throw new ArgumentNullException(nameof(tag));
            }

            if (plaintext.Length != ciphertext.Length)
            {
                throw new ArgumentException("Plaintext and ciphertext must have the same length.");
            }

            if (nonce.Length != NonceSize)
            {
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            }
            if (tag.Length != TagSize)
            {
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
            }
        }
    }
}
