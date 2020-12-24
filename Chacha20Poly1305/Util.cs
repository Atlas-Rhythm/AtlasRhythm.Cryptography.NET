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

using System;

namespace Chacha20Poly1305
{
    internal static class Extensions
    {
        public static uint LeftRoll(this uint lhs, int rhs) => (lhs << rhs) | (lhs >> (sizeof(uint) * 8 - rhs));
    }

    internal static class LittleEndianBitConverter
    {
        public static uint ToUInt32(byte[] value, int startIndex)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt32(value, startIndex);
            }
            else
            {
                return value[startIndex]
                    | ((uint)value[startIndex + 1] << 8)
                    | ((uint)value[startIndex + 2] << 16)
                    | ((uint)value[startIndex + 3] << 24);
            }
        }

        public static byte[] GetBytes(uint value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.GetBytes(value);
            }
            else
            {
                return new byte[]
                {
                    (byte)(value & 0x00_00_00_FF),
                    (byte)((value & 0x00_00_FF_00) >> 8),
                    (byte)((value & 0x00_FF_00_00) >> 16),
                    (byte)((value & 0xFF_00_00_00) >> 24)
                };
            }
        }

        public static byte[] GetBytes(ulong value)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.GetBytes(value);
            }
            else
            {
                return new byte[]
                {
                    (byte)(value & 0x00_00_00_00_00_00_00_FF),
                    (byte)((value & 0x00_00_00_00_00_00_FF_00) >> 8),
                    (byte)((value & 0x00_00_00_00_00_FF_00_00) >> 16),
                    (byte)((value & 0x00_00_00_00_FF_00_00_00) >> 24),
                    (byte)((value & 0x00_00_00_FF_00_00_00_00) >> 32),
                    (byte)((value & 0x00_00_FF_00_00_00_00_00) >> 40),
                    (byte)((value & 0x00_FF_00_00_00_00_00_00) >> 48),
                    (byte)((value & 0xFF_00_00_00_00_00_00_00) >> 56)
                };
            }
        }
    }
}
