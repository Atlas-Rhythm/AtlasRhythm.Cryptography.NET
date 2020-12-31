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

using AtlasRhythm.Cryptography.Ciphers;
using AtlasRhythm.Cryptography.Macs;
using System;
using System.Security.Cryptography;

namespace AtlasRhythm.Cryptography.Aeads
{
    /// <summary>
    /// Represents a key to be used with ChaCha20 and Poly1305 for Authenticated Encryption with Associated Data.
    /// </summary>
    /// <example>
    /// The following example demonstrates how to encrypt and decrypt a sample string using the <see cref="Chacha20Poly1305"/> class.
    /// <code>
    /// using AtlasRhythm.Cryptography.Aeads;
    /// using System.Security.Cryptography;
    /// using System.Text;
    /// 
    /// // Create a new cryptographically secure random number generator
    /// var rng = new RNGCryptoServiceProvider();
    /// 
    /// // Generate a random key of the appropriate length
    /// var key = new byte[Chacha20Poly1305.KeySize];
    /// rng.GetBytes(key);
    /// 
    /// // Create the instance
    /// // Note the `using var`, this is necessary to make sure
    /// // the memory containing the key is zeroed after use
    /// using var aead = new Chacha20Poly1305(key);
    /// 
    /// // Generate a random nonce of the appropriate length
    /// // A nonce must *never* be used twice with the same key
    /// var nonce = new byte[Chacha20Poly1305.NonceSize];
    /// rng.GetBytes(nonce);
    /// 
    /// // Obtain the plaintext (content to encrypt) and associated data
    /// // The associated data is just used as additional authentication security
    /// // and is optional
    /// var plaintext = Encoding.UTF8.GetBytes("very secret plaintext");
    /// var associatedData = Encoding.UTF8.GetBytes("very secret associated data");
    /// 
    /// // Encrypt the plaintext and return a buffer containing
    /// // the ciphertext (encrypted contents) and the authentication tag
    /// var output = aead.Encrypt(nonce, plaintext, associatedData);
    /// 
    /// // Decrypt and authenticate the previously obtained output
    /// string decryptedPlaintext;
    /// try
    /// {
    ///     newPlaintext = Encoding.UTF8.GetString(aead.Decrypt(nonce, output, associatedData));
    /// }
    /// catch (CryptographicException ex)
    /// {
    ///     // An exception will be thrown if the authentication tag can't be verified
    ///     // This usually means the contents have been tampered with
    /// }
    /// </code>
    /// </example>
    public sealed class Chacha20Poly1305 : Aead, IDisposable
    {
        /// <summary>
        /// Key size, in bytes, supported by this instance.
        /// </summary>
        public const int KeySize = Chacha20Core.KeySize;
        /// <summary>
        /// Nonce size, in bytes, supported by this instance.
        /// </summary>
        public const int NonceSize = Chacha20Core.NonceSize;
        /// <summary>
        /// Tag size, in bytes, supported by this instance.
        /// </summary>
        public const int TagSize = Poly1305Core.TagSize;

        public override KeySizes KeyByteSizes { get; } = new KeySizes(KeySize, KeySize, 0);
        public override KeySizes NonceByteSizes { get; } = new KeySizes(NonceSize, NonceSize, 0);
        public override KeySizes TagByteSizes { get; } = new KeySizes(TagSize, TagSize, 0);

        protected override byte[] Key { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Chacha20Poly1305"/> class with a provided key.
        /// </summary>
        /// <param name="key">The secret key to use for this instance.</param>
        /// <exception cref="ArgumentNullException">The `key` parameter is `null`.</exception>
        /// <exception cref="CryptographicException">The key parameter length is other than 32 bytes (256 bits).</exception>
        public Chacha20Poly1305(byte[] key)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySize)
                throw new CryptographicException("Specified key is not a valid size for this algorithm.");
            Key = key;
        }

        protected override unsafe void EncryptCore(
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
            uint* chacha20State = stackalloc uint[Chacha20Core.StateSize];

            for (i = 0; i < size; ++i) ciphertext[i] = plaintext[i];
            Chacha20Core.State(chacha20State, key, 1, nonce);
            Chacha20Core.Cipher(chacha20State, ciphertext, size);

            chacha20State[12] = 0;
            Tag(ciphertext, size, associatedData, associatedDataSize, chacha20State, tag);

            for (i = 4; i < Chacha20Core.StateSize; ++i) chacha20State[i] = 0;
        }

        protected override unsafe bool DecryptCore(
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
            uint* chacha20State = stackalloc uint[Chacha20Core.StateSize];
            byte* computedTag = stackalloc byte[Poly1305Core.TagSize];

            Chacha20Core.State(chacha20State, key, 0, nonce);
            Tag(ciphertext, size, associatedData, associatedDataSize, chacha20State, computedTag);
            bool valid = Poly1305Core.Verify(tag, computedTag);

            if (valid)
            {
                for (i = 0; i < size; ++i) plaintext[i] = ciphertext[i];
                chacha20State[12] = 1;
                Chacha20Core.Cipher(chacha20State, plaintext, size);
            }

            for (i = 4; i < Chacha20Core.StateSize; ++i) chacha20State[i] = 0;
            for (i = 0; i < Poly1305Core.TagSize; ++i) computedTag[i] = 0;

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
            byte* poly1305key = stackalloc byte[Poly1305Core.KeySize];
            byte* padding = stackalloc byte[Poly1305Core.BlockSize - 1];
            byte* u64 = stackalloc byte[sizeof(ulong)];

            Chacha20Core.Cipher(chacha20State, poly1305key, Poly1305Core.KeySize);

            int padding1 = Poly1305Core.BlockSize - (associatedDataSize % Poly1305Core.BlockSize);
            int padding2 = Poly1305Core.BlockSize - (ciphertextSize % Poly1305Core.BlockSize);

            Poly1305Core.State poly1305State;
            Poly1305Core.Init(&poly1305State, poly1305key);

            Poly1305Core.Update(&poly1305State, associatedData, associatedDataSize);
            Poly1305Core.Update(&poly1305State, padding, padding1);

            Poly1305Core.Update(&poly1305State, ciphertext, ciphertextSize);
            Poly1305Core.Update(&poly1305State, padding, padding2);

            Memory.U64ToU8((ulong)associatedDataSize, u64);
            Poly1305Core.Update(&poly1305State, u64, sizeof(ulong));

            Memory.U64ToU8((ulong)ciphertextSize, u64);
            Poly1305Core.Update(&poly1305State, u64, sizeof(ulong));

            Poly1305Core.Finish(&poly1305State, tag);

            for (i = 0; i < Poly1305Core.KeySize; ++i) poly1305key[i] = 0;
        }

        public void Dispose()
        {
            for (int i = 0; i < KeySize; ++i) Key[i] = 0;
        }
    }
}
