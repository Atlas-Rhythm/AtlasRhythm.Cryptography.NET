using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using System;
using System.Security.Cryptography;

namespace AtlasRhythm.Cryptography.Benchmarks
{
    [SimpleJob(RuntimeMoniker.NetCoreApp50, baseline: true)]
    [SimpleJob(RuntimeMoniker.CoreRt50)]
    [RPlotExporter]
    public class Chacha20Poly1305Benchmarks
    {
        private Chacha20Poly1305 chacha20Poly1305;
        private AesGcm aesGcm;

        private byte[] key;
        private byte[] nonce;
        private byte[] plaintext;
        private byte[] ciphertext;
        private byte[] computedPlaintext;
        private byte[] tag;
        private byte[] associatedData;

        private NSec.Cryptography.Key nsecKey;
        private NSec.Cryptography.Nonce nsecNonce;

        [Params(1024, 1024 * 1024)]
        public int N;

        [Benchmark(Baseline = true)]
        public void Chacha20Poly1305Roundtrip()
        {
            chacha20Poly1305.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag,
                associatedData);
            chacha20Poly1305.Decrypt(
                nonce,
                ciphertext,
                tag,
                computedPlaintext,
                associatedData);
        }

        [Benchmark]
        public void SodiumChacha20Poly1305Roundtrip()
        {
            NSec.Cryptography.AeadAlgorithm.ChaCha20Poly1305.Encrypt(nsecKey, nsecNonce, associatedData, plaintext, ciphertext);
            NSec.Cryptography.AeadAlgorithm.ChaCha20Poly1305.Decrypt(nsecKey, nsecNonce, associatedData, ciphertext, computedPlaintext);
        }

        [Benchmark]
        public void AesGcmRoundtrip()
        {
            aesGcm.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag,
                associatedData);
            aesGcm.Decrypt(
                nonce,
                ciphertext,
                tag,
                computedPlaintext,
                associatedData);
        }

        private Random Setup()
        {
            var rng = new Random(2112);

            plaintext = new byte[N];
            rng.NextBytes(plaintext);

            ciphertext = new byte[N];
            computedPlaintext = new byte[N];

            associatedData = new byte[12];
            rng.NextBytes(associatedData);

            return rng;
        }

        [GlobalSetup(Target = nameof(Chacha20Poly1305Roundtrip))]
        public void SetupChacha20Poly1305()
        {
            var rng = Setup();

            key = new byte[Chacha20Poly1305.KeySize];
            rng.NextBytes(key);

            nonce = new byte[Chacha20Poly1305.NonceSize];
            rng.NextBytes(nonce);

            tag = new byte[Chacha20Poly1305.TagSize];

            chacha20Poly1305 = new Chacha20Poly1305(key);
        }

        [GlobalSetup(Target = nameof(SodiumChacha20Poly1305Roundtrip))]
        public void SetupSodiumChacha20Poly1305()
        {
            var rng = Setup();

            key = new byte[NSec.Cryptography.AeadAlgorithm.ChaCha20Poly1305.KeySize];
            rng.NextBytes(key);
            nsecKey = NSec.Cryptography.Key.Import(
                NSec.Cryptography.AeadAlgorithm.ChaCha20Poly1305,
                key,
                NSec.Cryptography.KeyBlobFormat.RawSymmetricKey);

            nonce = new byte[NSec.Cryptography.AeadAlgorithm.ChaCha20Poly1305.NonceSize];
            rng.NextBytes(nonce);
            nsecNonce = new NSec.Cryptography.Nonce(
                new ReadOnlySpan<byte>(nonce, 0, 4),
                new ReadOnlySpan<byte>(nonce, 4, 8));

            ciphertext = new byte[ciphertext.Length + NSec.Cryptography.AeadAlgorithm.ChaCha20Poly1305.TagSize];
        }

        [GlobalSetup(Target = nameof(AesGcmRoundtrip))]
        public void SetupAesGcm()
        {
            var rng = Setup();

            key = new byte[256 / 8];
            rng.NextBytes(key);

            nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            rng.NextBytes(nonce);

            tag = new byte[AesGcm.TagByteSizes.MaxSize];

            aesGcm = new AesGcm(key);
        }

        [GlobalCleanup(Target = nameof(Chacha20Poly1305Roundtrip))]
        public void CleanupChacha20Poly1305()
        {
            chacha20Poly1305.Dispose();
        }

        [GlobalCleanup(Target = nameof(AesGcmRoundtrip))]
        public void CleanupAesGcm()
        {
            aesGcm.Dispose();
        }
    }
}
