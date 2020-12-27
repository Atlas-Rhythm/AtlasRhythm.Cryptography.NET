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

namespace AtlasRhythm.Cryptography
{
    internal static unsafe class Poly1305
    {
        public const int KeySize = 256 / 8;
        public const int TagSize = 128 / 8;
        public const int BlockSize = 16;

        public ref struct State
        {
            public fixed uint r[5];
            public fixed uint h[5];
            public fixed uint pad[4];
            public int leftover;
            public fixed byte buffer[BlockSize];
            public bool final;
        }

        public static bool Verify(byte* mac1, byte* mac2)
        {
            int i;
            uint diff = 0;

            for (i = 0; i < TagSize; i++) diff |= (uint)(mac1[i] ^ mac2[i]);
            diff = (diff - 1) >> ((sizeof(uint) * 8) - 1);
            return (diff & 1) != 0;
        }

        public static void Update(State* state, byte* data, int size)
        {
            int i;

            if (state->leftover != 0)
            {
                int want = BlockSize - state->leftover;

                if (want > size) want = size;
                for (i = 0; i < want; ++i) state->buffer[state->leftover + i] = data[i];

                size -= want;
                data += want;

                state->leftover += want;
                if (state->leftover < BlockSize) return;
                
                Blocks(state, state->buffer, BlockSize);
                state->leftover = 0;
            }

            if (size >= BlockSize)
            {
                int want = size & ~(BlockSize - 1);
                Blocks(state, data, want);
                data += want;
                size -= want;
            }

            if (size != 0)
            {
                for (i = 0; i < size; ++i) state->buffer[state->leftover + i] = data[i];
                state->leftover += size;
            }
        }

        public static void Init(State* state, byte* key)
        {
            state->r[0] =  Memory.U8ToU32(key)            & 0x3ffffff;
            state->r[1] = (Memory.U8ToU32(key +  3) >> 2) & 0x3ffff03;
            state->r[2] = (Memory.U8ToU32(key +  6) >> 4) & 0x3ffc0ff;
            state->r[3] = (Memory.U8ToU32(key +  9) >> 6) & 0x3f03fff;
            state->r[4] = (Memory.U8ToU32(key + 12) >> 8) & 0x00fffff;

            state->pad[0] = Memory.U8ToU32(key + 16);
            state->pad[1] = Memory.U8ToU32(key + 20);
            state->pad[2] = Memory.U8ToU32(key + 24);
            state->pad[3] = Memory.U8ToU32(key + 28);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void Finish(State* state, byte* mac)
        {
            uint h0, h1, h2, h3, h4, c;
            uint g0, g1, g2, g3, g4;
            ulong f;
            uint mask;

            if (state->leftover != 0)
            {
                int i = state->leftover;
                state->buffer[i++] = 1;
                for (; i < BlockSize; ++i) state->buffer[i] = 0;
                state->final = true;
                Blocks(state, state->buffer, BlockSize);
            }

            h0 = state->h[0];
            h1 = state->h[1];
            h2 = state->h[2];
            h3 = state->h[3];
            h4 = state->h[4];

                         c = h1 >> 26; h1 &= 0x3ffffff;
            h2 += c;     c = h2 >> 26; h2 &= 0x3ffffff;
            h3 += c;     c = h3 >> 26; h3 &= 0x3ffffff;
            h4 += c;     c = h4 >> 26; h4 &= 0x3ffffff;
            h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
            h1 += c;

            g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
            g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
            g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
            g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
            g4 = h4 + c - (1u << 26);

            mask = (g4 >> ((sizeof(uint) * 8) - 1)) - 1;
            g0 &= mask;
            g1 &= mask;
            g2 &= mask;
            g3 &= mask;
            g4 &= mask;
            mask = ~mask;
            h0 = (h0 & mask) | g0;
            h1 = (h1 & mask) | g1;
            h2 = (h2 & mask) | g2;
            h3 = (h3 & mask) | g3;
            h4 = (h4 & mask) | g4;

            h0 =  (h0        | (h1 << 26)) & 0xffffffff;
            h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
            h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
            h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

            f = (ulong)h0 + state->pad[0];             h0 = (uint)f;
            f = (ulong)h1 + state->pad[1] + (f >> 32); h1 = (uint)f;
            f = (ulong)h2 + state->pad[2] + (f >> 32); h2 = (uint)f;
            f = (ulong)h3 + state->pad[3] + (f >> 32); h3 = (uint)f;

            Memory.U32ToU8(h0, mac);
            Memory.U32ToU8(h1, mac +  4);
            Memory.U32ToU8(h2, mac +  8);
            Memory.U32ToU8(h3, mac + 12);

            state->h[0] = 0;
            state->h[1] = 0;
            state->h[2] = 0;
            state->h[3] = 0;
            state->h[4] = 0;
            state->r[0] = 0;
            state->r[1] = 0;
            state->r[2] = 0;
            state->r[3] = 0;
            state->r[4] = 0;
            state->pad[0] = 0;
            state->pad[1] = 0;
            state->pad[2] = 0;
            state->pad[3] = 0;
        }


#if NET5_0 || NETCOREAPP3_1
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
#endif
        private static void Blocks(State* state, byte* data, int size)
        {
            uint hibit = state->final ? 0 : (1u << 24);
            uint r0, r1, r2, r3, r4;
            uint s1, s2, s3, s4;
            uint h0, h1, h2, h3, h4;
            ulong d0, d1, d2, d3, d4;
            uint c;

            r0 = state->r[0];
            r1 = state->r[1];
            r2 = state->r[2];
            r3 = state->r[3];
            r4 = state->r[4];

            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            h0 = state->h[0];
            h1 = state->h[1];
            h2 = state->h[2];
            h3 = state->h[3];
            h4 = state->h[4];

            while (size >= BlockSize)
            {
                h0 +=  Memory.U8ToU32(data)            & 0x3ffffff;
                h1 += (Memory.U8ToU32(data +  3) >> 2) & 0x3ffffff;
                h2 += (Memory.U8ToU32(data +  6) >> 4) & 0x3ffffff;
                h3 += (Memory.U8ToU32(data +  9) >> 6) & 0x3ffffff;
                h4 += (Memory.U8ToU32(data + 12) >> 8) | hibit;

                d0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3* s2 + (ulong)h4* s1;
                d1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3* s3 + (ulong)h4* s2;
                d2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3* s4 + (ulong)h4* s3;
                d3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3* r0 + (ulong)h4* s4;
                d4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3* r1 + (ulong)h4* r0;

                         c = (uint)(d0 >> 26); h0 = (uint)d0 & 0x3ffffff;
                d1 += c; c = (uint)(d1 >> 26); h1 = (uint)d1 & 0x3ffffff;
                d2 += c; c = (uint)(d2 >> 26); h2 = (uint)d2 & 0x3ffffff;
                d3 += c; c = (uint)(d3 >> 26); h3 = (uint)d3 & 0x3ffffff;
                d4 += c; c = (uint)(d4 >> 26); h4 = (uint)d4 & 0x3ffffff;
                h0 += c * 5;
                c = h0 >> 26;
                h0 &= 0x3ffffff;
                h1 += c;

                data += BlockSize;
                size -= BlockSize;
            }

            state->h[0] = h0;
            state->h[1] = h1;
            state->h[2] = h2;
            state->h[3] = h3;
            state->h[4] = h4;
        }
    }
}
