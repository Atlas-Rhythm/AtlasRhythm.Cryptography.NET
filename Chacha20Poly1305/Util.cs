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
                    (byte)(value & 0x00_00_00_FF),
                    (byte)((value & 0x00_00_FF_00) >> 8),
                    (byte)((value & 0x00_FF_00_00) >> 16),
                    (byte)((value & 0xFF_00_00_00) >> 24)
                };
            }
        }
    }
}
