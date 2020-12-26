using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using System;
using System.Security.Cryptography;

namespace Chacha20Poly1305.Benchmarks
{
    [SimpleJob(RuntimeMoniker.NetCoreApp50, baseline: true)]
    [SimpleJob(RuntimeMoniker.CoreRt50)]
    public class Benchmarks
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

        [Params(1024, 1024 * 1024)]
        public int N;

        [Benchmark(Baseline = true)]
        public void Chacha20Poly1305Roundtrip()
        {
            chacha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            chacha20Poly1305.Decrypt(nonce, ciphertext, tag, computedPlaintext, associatedData);
        }

        [Benchmark]
        public void AesGcmRoundtrip()
        {
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            aesGcm.Decrypt(nonce, ciphertext, tag, computedPlaintext, associatedData);
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
