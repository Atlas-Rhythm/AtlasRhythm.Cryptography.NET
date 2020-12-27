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

#if NET5_0 || NETCOREAPP3_1
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace AtlasRhythm.Cryptography
{
    internal static unsafe class Chacha20
    {
        public const int KeySize = 256 / 8;
        public const int NonceSize = 96 / 8;

        public const int StateSize = 16;
        public const int StateBytesSize = StateSize * sizeof(uint);
        public const int Rounds = 20;

        public static void State(uint* state, byte* key, uint counter, byte* nonce)
        {
            state[ 0] = 0x61707865;
            state[ 1] = 0x3320646e;
            state[ 2] = 0x79622d32;
            state[ 3] = 0x6b206574;

            state[ 4] = Memory.U8ToU32(key);
            state[ 5] = Memory.U8ToU32(key +     sizeof(uint));
            state[ 6] = Memory.U8ToU32(key + 2 * sizeof(uint));
            state[ 7] = Memory.U8ToU32(key + 3 * sizeof(uint));
            state[ 8] = Memory.U8ToU32(key + 4 * sizeof(uint));
            state[ 9] = Memory.U8ToU32(key + 5 * sizeof(uint));
            state[10] = Memory.U8ToU32(key + 6 * sizeof(uint));
            state[11] = Memory.U8ToU32(key + 7 * sizeof(uint));

            state[12] = counter;

            state[13] = Memory.U8ToU32(nonce);
            state[14] = Memory.U8ToU32(nonce +     sizeof(uint));
            state[15] = Memory.U8ToU32(nonce + 2 * sizeof(uint));
        }

#if NET5_0 || NETCOREAPP3_1
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
#endif
        public static void Cipher(uint* state, byte* data, int size)
        {
            int i;
            byte* temp = null;
            byte* buffer = stackalloc byte[StateBytesSize];

#if NET5_0 || NETCOREAPP3_1
            if (Sse2.IsSupported)
            {

                Vector128<uint> s0, s1, s2, s3;
                Vector128<uint> x0, x1, x2, x3;
                Vector128<uint> inc = Vector128.CreateScalar(1u);
                
                s0 = Sse2.LoadVector128(state);
                s1 = Sse2.LoadVector128(state + 4);
                s2 = Sse2.LoadVector128(state + 8);
                s3 = Sse2.LoadVector128(state + 12);
                
                while (true)
                {
                    if (size < StateBytesSize)
                    {
                        for (i = 0; i < size; ++i) buffer[i] = data[i];
                        temp = data;
                        data = buffer;
                    }
                
                    x0 = s0;
                    x1 = s1;
                    x2 = s2;
                    x3 = s3;
                
                    for (i = 0; i < Rounds; i += 2)
                    {
                        x0 = Sse2.Add(x0, x1); x3 = Sse2.Xor(x3, x0); x3 = Sse2.Xor(Sse2.ShiftLeftLogical(x3, 16), Sse2.ShiftRightLogical(x3, 16));
                        x2 = Sse2.Add(x2, x3); x1 = Sse2.Xor(x1, x2); x1 = Sse2.Xor(Sse2.ShiftLeftLogical(x1, 12), Sse2.ShiftRightLogical(x1, 20));
                        x0 = Sse2.Add(x0, x1); x3 = Sse2.Xor(x3, x0); x3 = Sse2.Xor(Sse2.ShiftLeftLogical(x3,  8), Sse2.ShiftRightLogical(x3, 24));
                        x2 = Sse2.Add(x2, x3); x1 = Sse2.Xor(x1, x2); x1 = Sse2.Xor(Sse2.ShiftLeftLogical(x1,  7), Sse2.ShiftRightLogical(x1, 25));
                        x1 = Sse2.Shuffle(x1, 0b00111001);
                        x2 = Sse2.Shuffle(x2, 0b01001110);
                        x3 = Sse2.Shuffle(x3, 0b10010011);

                        x0 = Sse2.Add(x0, x1); x3 = Sse2.Xor(x3, x0); x3 = Sse2.Xor(Sse2.ShiftLeftLogical(x3, 16), Sse2.ShiftRightLogical(x3, 16));
                        x2 = Sse2.Add(x2, x3); x1 = Sse2.Xor(x1, x2); x1 = Sse2.Xor(Sse2.ShiftLeftLogical(x1, 12), Sse2.ShiftRightLogical(x1, 20));
                        x0 = Sse2.Add(x0, x1); x3 = Sse2.Xor(x3, x0); x3 = Sse2.Xor(Sse2.ShiftLeftLogical(x3,  8), Sse2.ShiftRightLogical(x3, 24));
                        x2 = Sse2.Add(x2, x3); x1 = Sse2.Xor(x1, x2); x1 = Sse2.Xor(Sse2.ShiftLeftLogical(x1,  7), Sse2.ShiftRightLogical(x1, 25));
                        x1 = Sse2.Shuffle(x1, 0b10010011);
                        x2 = Sse2.Shuffle(x2, 0b01001110);
                        x3 = Sse2.Shuffle(x3, 0b00111001);
                    }

                    x0 = Sse2.Add(x0, s0);
                    x1 = Sse2.Add(x1, s1);
                    x2 = Sse2.Add(x2, s2);
                    x3 = Sse2.Add(x3, s3);
                    
                    s3 = Sse2.Add(s3, inc);
                    
                    x0 = Sse2.Xor(x0, Sse2.LoadVector128((uint*)data)); Sse2.Store((uint*)data, x0); data += sizeof(uint) * 4;
                    x1 = Sse2.Xor(x1, Sse2.LoadVector128((uint*)data)); Sse2.Store((uint*)data, x1); data += sizeof(uint) * 4;
                    x2 = Sse2.Xor(x2, Sse2.LoadVector128((uint*)data)); Sse2.Store((uint*)data, x2); data += sizeof(uint) * 4;
                    x3 = Sse2.Xor(x3, Sse2.LoadVector128((uint*)data)); Sse2.Store((uint*)data, x3); data += sizeof(uint) * 4;
                    
                    if (size <= StateBytesSize)
                    {
                        if (size < StateBytesSize)
                        {
                            for (i = 0; i < size; ++i) temp[i] = buffer[i];
                            for (i = 0; i < StateBytesSize; ++i) buffer[i] = 0;
                        }
                    
                        state[12] = s3.GetElement(0);
                        return;
                    }
                    
                    size -= StateBytesSize;
                }

            }
            else
            {
#endif

                uint s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
                uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
                
                s0  = state[ 0];
                s1  = state[ 1];
                s2  = state[ 2];
                s3  = state[ 3];
                s4  = state[ 4];
                s5  = state[ 5];
                s6  = state[ 6];
                s7  = state[ 7];
                s8  = state[ 8];
                s9  = state[ 9];
                s10 = state[10];
                s11 = state[11];
                s12 = state[12];
                s13 = state[13];
                s14 = state[14];
                s15 = state[15];
                
                while (true)
                {
                    if (size < StateBytesSize)
                    {
                        for (i = 0; i < size; ++i) buffer[i] = data[i];
                        temp = data;
                        data = buffer;
                    }
                
                    x0  = s0;
                    x1  = s1;
                    x2  = s2;
                    x3  = s3;
                    x4  = s4;
                    x5  = s5;
                    x6  = s6;
                    x7  = s7;
                    x8  = s8;
                    x9  = s9;
                    x10 = s10;
                    x11 = s11;
                    x12 = s12;
                    x13 = s13;
                    x14 = s14;
                    x15 = s15;
                
                    for (i = 0; i < Rounds; i += 2)
                    {
                        QuarterRound(ref x0, ref x4, ref  x8, ref x12);
                        QuarterRound(ref x1, ref x5, ref  x9, ref x13);
                        QuarterRound(ref x2, ref x6, ref x10, ref x14);
                        QuarterRound(ref x3, ref x7, ref x11, ref x15);
                        QuarterRound(ref x0, ref x5, ref x10, ref x15);
                        QuarterRound(ref x1, ref x6, ref x11, ref x12);
                        QuarterRound(ref x2, ref x7, ref  x8, ref x13);
                        QuarterRound(ref x3, ref x4, ref  x9, ref x14);
                    }
                
                    x0  += s0;
                    x1  += s1;
                    x2  += s2;
                    x3  += s3;
                    x4  += s4;
                    x5  += s5;
                    x6  += s6;
                    x7  += s7;
                    x8  += s8;
                    x9  += s9;
                    x10 += s10;
                    x11 += s11;
                    x12 += s12;
                    x13 += s13;
                    x14 += s14;
                    x15 += s15;
                
                    s12++;
                
                    x0  ^= Memory.U8ToU32(data); Memory.U32ToU8(x0,  data); data += sizeof(uint);
                    x1  ^= Memory.U8ToU32(data); Memory.U32ToU8(x1,  data); data += sizeof(uint);
                    x2  ^= Memory.U8ToU32(data); Memory.U32ToU8(x2,  data); data += sizeof(uint);
                    x3  ^= Memory.U8ToU32(data); Memory.U32ToU8(x3,  data); data += sizeof(uint);
                    x4  ^= Memory.U8ToU32(data); Memory.U32ToU8(x4,  data); data += sizeof(uint);
                    x5  ^= Memory.U8ToU32(data); Memory.U32ToU8(x5,  data); data += sizeof(uint);
                    x6  ^= Memory.U8ToU32(data); Memory.U32ToU8(x6,  data); data += sizeof(uint);
                    x7  ^= Memory.U8ToU32(data); Memory.U32ToU8(x7,  data); data += sizeof(uint);
                    x8  ^= Memory.U8ToU32(data); Memory.U32ToU8(x8,  data); data += sizeof(uint);
                    x9  ^= Memory.U8ToU32(data); Memory.U32ToU8(x9,  data); data += sizeof(uint);
                    x10 ^= Memory.U8ToU32(data); Memory.U32ToU8(x10, data); data += sizeof(uint);
                    x11 ^= Memory.U8ToU32(data); Memory.U32ToU8(x11, data); data += sizeof(uint);
                    x12 ^= Memory.U8ToU32(data); Memory.U32ToU8(x12, data); data += sizeof(uint);
                    x13 ^= Memory.U8ToU32(data); Memory.U32ToU8(x13, data); data += sizeof(uint);
                    x14 ^= Memory.U8ToU32(data); Memory.U32ToU8(x14, data); data += sizeof(uint);
                    x15 ^= Memory.U8ToU32(data); Memory.U32ToU8(x15, data); data += sizeof(uint);
                    
                    if (size <= StateBytesSize)
                    {
                        if (size < StateBytesSize)
                        {
                            for (i = 0; i < size; ++i) temp[i] = buffer[i];
                            for (i = 0; i < StateBytesSize; ++i) buffer[i] = 0;
                        }
                
                        state[12] = s12;
                        return;
                    }
                
                    size -= StateBytesSize;
                }

#if NET5_0 || NETCOREAPP3_1
            }
#endif
        }

#if !NET35
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d ^= a; d = d.LeftRoll(16);
            c += d; b ^= c; b = b.LeftRoll(12);
            a += b; d ^= a; d = d.LeftRoll( 8);
            c += d; b ^= c; b = b.LeftRoll( 7);
        }
    }
}
