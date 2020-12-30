using System;

namespace AtlasRhythm.Cryptography.Tests
{
    internal static class TestHelpers
    {
        public static void SetEnv(bool sse2, bool avx2)
        {
            if (!sse2) Environment.SetEnvironmentVariable(Debug.NoSse2Var, "X");
            if (!avx2) Environment.SetEnvironmentVariable(Debug.NoAvx2Var, "X");
        }

        public static void ClearEnv()
        {
            Environment.SetEnvironmentVariable(Debug.NoSse2Var, null);
            Environment.SetEnvironmentVariable(Debug.NoAvx2Var, null);
        }
    }
}
