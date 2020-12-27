# Chacha20Poly1305.NET

Pure C#, performant and [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant implementation of ChaCha20 and Poly1305 for Authenticated Encryption with Associated Data (AEAD).

> No security audits of this code have ever been performed. USE AT YOUR OWN RISK.

[![Tests Status](https://img.shields.io/github/workflow/status/Atlas-Rhythm/Chacha20Poly1305.NET/Tests?label=tests&style=for-the-badge)](https://github.com/Atlas-Rhythm/Chacha20Poly1305.NET/actions?query=workflow%3ATests)

ChaCha20 is stream cipher which is faster than AES in software-only implementations. Poly1305 is a fast message authentication code (MAC). They can be combined to achieve Authenticated Encryption with Associated Data (AEAD) as a fast software-only alternative to AES in Galois Counter Mode (GCM).

This library aims to be a portable, fast and correct implementation which can easily be integrated into any .NET project as an alternative to AES-GCM. It supports .NET Standard 1.3 and up and .NET Framework 3.5 and up. The public API tries to replicate that of .NET Standard 2.1's [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=netstandard-2.1). Implementation is based on libsodium. Neither encryption or decryption allocate and sensitive information is zeroed from memory before freeing resources.

## Usage

### Example

```cs
using AtlasRhythm.Cryptography;
using System.Security.Cryptography;

// Create a new cryptographically secure random number generator
var rng = new RNGCryptoServiceProvider();

// Generate a random key of the appropriate length
var key = new byte[Chacha20Poly1305.KeySize];
rng.GetBytes(key);

// Create the instance
// Note the `using var`, this is necessary to make sure
// the memory containing the key is zeroed after use
using var aead = new Chacha20Poly1305(key);

// Generate a random nonce of the appropriate length
// A nonce must *never* be used twice with the same key
var nonce = new byte[Chacha20Poly1305.NonceSize];
rng.GetBytes(nonce);

// Obtain the plaintext (content to encrypt) and associated data somehow
// The associated data is just used as additional authentication security
// and is optional
var plaintext = ...;
var associatedData = ...;

// Encrypt the plaintext and return a buffer containing
// the ciphertext (encrypted contents) and the authentication tag
var output = aead.Encrypt(nonce, plaintext, associatedData);

// Decrypt and authenticate the previously obtained output
byte[] newPlaintext;
try
{
    newPlaintext = aead.Decrypt(nonce, output, associatedData);
}
catch (CryptographicException ex)
{
    // An exception will be thrown if the authentication tag can't be verified
    // This usually means the contents have been tampered with
}
```

## Tests

The solution contains an extensive test suite using [test vectors from the RFC](https://tools.ietf.org/html/rfc8439#section-2.8.2) and random data.

To run the tests, simply run `dotnet test` from the [Chacha20Poly1305.Tests](Chacha20Poly1305.Tests) directory.

## Benchmarks

The benchmarks compare performance against .NET's [AesGcm](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=netstandard-2.1) and NSec's (libsodium) [Chacha20Poly1305](https://nsec.rocks/docs/api/nsec.cryptography.aeadalgorithm#chacha20poly1305) on .NET 5.0 and CoreRT 5.0.

They can be run from the [Chacha20Poly1305.Benchmarks](Chacha20Poly1305.Benchmarks) directory by running `dotnet run -c Release`.

[Sample results](BenchmarkResults.md)

## License

This code is distributed under the terms of the [Apache License (Version 2.0)](LICENSE).
