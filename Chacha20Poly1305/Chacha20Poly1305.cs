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
    public sealed class Chacha20Poly1305
    {
        private const int KeySize = Chacha20.KeySize;
        private const int NonceSize = Chacha20.NonceSize;
        private const int TagSize = Poly1305.TagSize;

        public static KeySizes KeyByteSizes { get; } = new KeySizes(KeySize, KeySize, 1);
        public static KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 1);
        public static KeySizes TagByteSizes { get; } = new KeySizes(TagSize, TagSize, 1);

        private readonly byte[] key;

        public Chacha20Poly1305(byte[] key)
        {
            CheckKey(key);
            this.key = key;
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = default)
        {
            CheckParameters(nonce, plaintext, ciphertext, tag);

            Array.Copy(plaintext, ciphertext, plaintext.Length);
            Chacha20.Cipher(key, 1, nonce, ciphertext);

            var poly1305Message = Poly1305MessageGen(associatedData, ciphertext);
            var poly1305Key = Poly1305KeyGen(key, nonce);
            Poly1305.Mac(poly1305Message, poly1305Key, tag);
        }

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

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = default)
        {
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

            if (nonce.Length != NonceSize)
            {
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            }

            if (plaintext.Length != ciphertext.Length)
            {
                throw new ArgumentException("Plaintext and ciphertext must have the same length.");
            }

            if (tag.Length != TagSize)
            {
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
            }
        }
    }
}
