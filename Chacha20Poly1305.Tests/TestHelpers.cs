using System;

namespace AtlasRhythm.Cryptography.Tests
{
    internal static class TestHelpers
    {
        public static void SetEnv(bool sse2, bool avx2)
        {
            if (!sse2) Environment.SetEnvironmentVariable(Chacha20Poly1305.NoSse2Var, "X");
            if (!avx2) Environment.SetEnvironmentVariable(Chacha20Poly1305.NoAvx2Var, "X");
        }

        public static void ClearEnv()
        {
            Environment.SetEnvironmentVariable(Chacha20Poly1305.NoSse2Var, null);
            Environment.SetEnvironmentVariable(Chacha20Poly1305.NoAvx2Var, null);
        }
    }
}
