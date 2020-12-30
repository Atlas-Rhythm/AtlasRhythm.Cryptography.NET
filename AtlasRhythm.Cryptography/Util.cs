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

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

#if (NET5_0 || NETCOREAPP3_1) && DEBUG
using System.Runtime.Intrinsics;
#endif

namespace AtlasRhythm.Cryptography
{
    internal static class Extensions
    {
#if !NET35
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static uint LeftRoll(this uint lhs, int rhs) =>
            (lhs << rhs) | (lhs >> (sizeof(uint) * 8 - rhs));

        public static bool IsLegalSize(this int size, KeySizes legalSizes)
        {
            if (legalSizes.SkipSize == 0 && legalSizes.MinSize == size) return true;
            else if (size >= legalSizes.MinSize && size <= legalSizes.MaxSize)
            {
                int delta = size - legalSizes.MinSize;
                if (delta % legalSizes.SkipSize == 0) return true;
            }

            return false;
        }
    }

    internal static unsafe class Memory
    {
#if !NET35
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static uint U8ToU32(byte* u8) =>
                  u8[0]       |
            (uint)u8[1] <<  8 |
            (uint)u8[2] << 16 |
            (uint)u8[3] << 24;

#if !NET35
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void U32ToU8(uint u32, byte* u8)
        {
            u8[0] = (byte) (u32        & 0xff);
            u8[1] = (byte)((u32 >>  8) & 0xff);
            u8[2] = (byte)((u32 >> 16) & 0xff);
            u8[3] = (byte) (u32 >> 24);
        }

#if !NET35
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void U64ToU8(ulong u64, byte* u8)
        {
            u8[0] = (byte) (u64        & 0xff);
            u8[1] = (byte)((u64 >>  8) & 0xff);
            u8[2] = (byte)((u64 >> 16) & 0xff);
            u8[3] = (byte)((u64 >> 24) & 0xff);
            u8[4] = (byte)((u64 >> 32) & 0xff);
            u8[5] = (byte)((u64 >> 40) & 0xff);
            u8[6] = (byte)((u64 >> 48) & 0xff);
            u8[7] = (byte) (u64 >> 56);
        }
    }

#if DEBUG
    public static class Debug
    {
        public const string NoSse2Var = "NO_SSE2";
        public const string NoAvx2Var = "NO_AVX2";

#if NET5_0 || NETCOREAPP3_1
        internal static void PrintVector(Vector128<uint> v)
        {
            for (int i = 0; i < 4; ++i)
                System.Diagnostics.Debug.Write($"{v.GetElement(i):x8} ");
            System.Diagnostics.Debug.WriteLine("");
        }

        internal static void PrintVector(Vector256<uint> v)
        {
            for (int i = 0; i < 8; ++i)
                System.Diagnostics.Debug.Write($"{v.GetElement(i):x8} ");
            System.Diagnostics.Debug.WriteLine("");
        }
#endif
    }
#endif
}
