using System;
using System.Security.Cryptography;

namespace AtlasRhythm.Cryptography.Aeads
{
    /// <summary>
    /// Represents the abstract class from which all implementations of Authenticated Encryption with Associated Data (AEAD) must derive.
    /// </summary>
    public abstract class Aead
    {
        /// <summary>
        /// Gets the key sizes, in bytes, supported by this instance.
        /// </summary>
        public abstract KeySizes KeyByteSizes { get; }
        /// <summary>
        /// Gets the nonce sizes, in bytes, supported by this instance.
        /// </summary>
        public abstract KeySizes NonceByteSizes { get; }
        /// <summary>
        /// Gets the tag sizes, in bytes, supported by this instance.
        /// </summary>
        public abstract KeySizes TagByteSizes { get; }

        protected abstract byte[] Key { get; }

        /// <summary>
        /// Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a separate buffer.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
        /// <param name="tag">The byte array to receive the generated authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <exception cref="ArgumentNullException">The `nonce`, `plaintext`, `ciphtertext`, or `tag` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `plaintext` parameter and the `ciphertext` do not have the same length.</exception>
        public void Encrypt(
            byte[] nonce,
            byte[] plaintext,
            byte[] ciphertext,
            byte[] tag,
            byte[] associatedData = default)
        {
            if (nonce is null) throw new ArgumentNullException(nameof(nonce));
            if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));
            if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
            if (tag is null) throw new ArgumentNullException(nameof(tag));

            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (!tag.Length.IsLegalSize(TagByteSizes))
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException("The plaintext and ciphertext must have the same length.");

            int size = ciphertext.Length;
            int associatedDataSize = associatedData is null ? 0 : associatedData.Length;

            unsafe
            {
                fixed (byte* k = Key, n = nonce, p = plaintext, a = associatedData, c = ciphertext, t = tag)
                    EncryptCore(k, n, p, size, a, associatedDataSize, c, t);
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
        /// <exception cref="ArgumentNullException">The `nonce`, `ciphertext`, `tag`, or `plaintext` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `ciphertext` parameter and the `plaintext` do not have the same length.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
        public void Decrypt(
            byte[] nonce,
            byte[] ciphertext,
            byte[] tag,
            byte[] plaintext,
            byte[] associatedData = default)
        {
            if (nonce is null) throw new ArgumentNullException(nameof(nonce));
            if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
            if (tag is null) throw new ArgumentNullException(nameof(tag));
            if (plaintext is null) throw new ArgumentNullException(nameof(plaintext)); ;

            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (!tag.Length.IsLegalSize(TagByteSizes))
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
            if (ciphertext.Length != plaintext.Length)
                throw new ArgumentException("The ciphertext and plaintext must have the same length.");

            int size = ciphertext.Length;
            int associatedDataSize = associatedData is null ? 0 : associatedData.Length;

            unsafe
            {
                fixed (byte* k = Key, n = nonce, c = ciphertext, t = tag, a = associatedData, p = plaintext)
                    if (!DecryptCore(k, n, c, size, t, a, associatedDataSize, p))
                        throw new CryptographicException("The computed and specified tags don't match.");
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
            if (nonce is null) throw new ArgumentNullException(nameof(nonce));
            if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));

            int size = plaintext.Length;
            int associatedDataSize = associatedData is null ? 0 : associatedData.Length;

            var ciphertextAndTag = new byte[size + TagByteSizes.MaxSize];

            unsafe
            {
                fixed (byte* k = Key, n = nonce, p = plaintext, a = associatedData, cat = ciphertextAndTag)
                    EncryptCore(k, n, p, size, a, associatedDataSize, cat, cat + size);
            }

            return ciphertextAndTag;
        }

        /// <summary>
        /// Decrypts the ciphertext and returns the plaintext in a new buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertextAndTag">The byte array containing the concatenated ciphertext and authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The byte array containing the plaintext.</returns>
        /// <exception cref="ArgumentNullException">The `nonce` or `ciphertextAndTag` parameter is `null`.</exception>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `ciphertextAndTag` parameter length is shorter than the tag length.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
        public byte[] Decrypt(byte[] nonce, byte[] ciphertextAndTag, byte[] associatedData = default)
        {
            if (nonce is null) throw new ArgumentNullException(nameof(nonce));
            if (ciphertextAndTag is null) throw new ArgumentNullException(nameof(ciphertextAndTag));

            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (ciphertextAndTag.Length < TagByteSizes.MaxSize)
                throw new ArgumentException("The specified ciphertext and tag are too short to fit a tag", nameof(ciphertextAndTag));

            int size = ciphertextAndTag.Length - TagByteSizes.MaxSize;
            int associatedDataSize = associatedData is null ? 0 : associatedData.Length;

            var plaintext = new byte[size];

            unsafe
            {
                fixed (byte* k = Key, n = nonce, cat = ciphertextAndTag, a = associatedData, p = plaintext)
                    if (!DecryptCore(k, n, cat, size, cat + size, a, associatedDataSize, p))
                        throw new CryptographicException("The computed and specified tags don't match.");
            }

            return plaintext;
        }

#if NET5_0 || NETCOREAPP3_1 || NETCOREAPP2_1 || NETSTANDARD2_1
        /// <summary>
        /// Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a separate buffer.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="ciphertext">The byte span to receive the encrypted contents.</param>
        /// <param name="tag">The byte span to receive the generated authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `plaintext` parameter and the `ciphertext` do not have the same length.</exception>
        public void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (!tag.Length.IsLegalSize(TagByteSizes))
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException("The plaintext and ciphertext must have the same length.");

            int size = ciphertext.Length;
            int associatedDataSize = associatedData.Length;

            unsafe
            {
                fixed (byte* k = Key, n = nonce, p = plaintext, a = associatedData, c = ciphertext, t = tag)
                    EncryptCore(k, n, p, size, a, associatedDataSize, c, t);
            }
        }

        /// <summary>
        /// Decrypts the ciphertext into the provided destination buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="tag">The authentication tag produced for this message during encryption.</param>
        /// <param name="plaintext">The byte span to receive the decrypted contents.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `tag` parameter length is not permitted by <see cref="TagByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `ciphertext` parameter and the `plaintext` do not have the same length.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
        public void Decrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData = default)
        {
            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (!tag.Length.IsLegalSize(TagByteSizes))
                throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
            if (ciphertext.Length != plaintext.Length)
                throw new ArgumentException("The ciphertext and plaintext must have the same length.");

            int size = ciphertext.Length;
            int associatedDataSize = associatedData.Length;

            unsafe
            {
                fixed (byte* k = Key, n = nonce, c = ciphertext, t = tag, a = associatedData, p = plaintext)
                    if (!DecryptCore(k, n, c, size, t, a, associatedDataSize, p))
                        throw new CryptographicException("The computed and specified tags don't match.");
            }
        }

        /// <summary>
        /// Encrypts the plaintext and returns the concatenated ciphertext and authentication tag in a new buffer.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <returns>The byte array containing the concatenated ciphertext and authentication tag.</returns>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        public byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));

            int size = plaintext.Length;
            int associatedDataSize = associatedData.Length;

            var ciphertextAndTag = new byte[size + TagByteSizes.MaxSize];

            unsafe
            {
                fixed (byte* k = Key, n = nonce, p = plaintext, a = associatedData, cat = ciphertextAndTag)
                    EncryptCore(k, n, p, size, a, associatedDataSize, cat, cat + size);
            }

            return ciphertextAndTag;
        }

        /// <summary>
        /// Decrypts the ciphertext and returns the plaintext in a new buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertextAndTag">The byte span containing the concatenated ciphertext and authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The byte array containing the plaintext.</returns>
        /// <exception cref="ArgumentException">The `nonce` parameter length is not permitted by <see cref="NonceByteSizes"/>.</exception>
        /// <exception cref="ArgumentException">The `ciphertextAndTag` parameter length is shorter than the tag length.</exception>
        /// <exception cref="CryptographicException">The tag value could not be verified.</exception>
        public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextAndTag, ReadOnlySpan<byte> associatedData = default)
        {
            if (!nonce.Length.IsLegalSize(NonceByteSizes))
                throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
            if (ciphertextAndTag.Length < TagByteSizes.MaxSize)
                throw new ArgumentException("The specified ciphertext and tag are too short to fit a tag", nameof(ciphertextAndTag));

            int size = ciphertextAndTag.Length - TagByteSizes.MaxSize;
            int associatedDataSize = associatedData.Length;

            var plaintext = new byte[size];

            unsafe
            {
                fixed (byte* k = Key, n = nonce, cat = ciphertextAndTag, a = associatedData, p = plaintext)
                    if (!DecryptCore(k, n, cat, size, cat + size, a, associatedDataSize, p))
                        throw new CryptographicException("The computed and specified tags don't match.");
            }

            return plaintext;
        }
#endif

        protected abstract unsafe void EncryptCore(
            byte* key,
            byte* nonce,
            byte* plaintext,
            int size,
            byte* associatedData,
            int associatedDataSize,
            byte* ciphertext,
            byte* tag);

        protected abstract unsafe bool DecryptCore(
            byte* key,
            byte* nonce,
            byte* ciphertext,
            int size,
            byte* tag,
            byte* associatedData,
            int associatedDataSize,
            byte* plaintext);
    }
}
