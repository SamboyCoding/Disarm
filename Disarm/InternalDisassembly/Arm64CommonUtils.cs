﻿using System.Collections;
using System.Linq;

namespace Disarm.InternalDisassembly;

/// <summary>
/// Helper functions common to various arm64 instructions.
/// The BitArray stuff in this class is Big-Endian - bit 0 is the most significant (leftmost) bit.
/// </summary>
internal static class Arm64CommonUtils
{
    public const int LOG2_TAG_GRANULE = 4;
    public const int TAG_GRANULE = 1 << LOG2_TAG_GRANULE;
    
    /// <summary>
    /// Extends the given bit array to the given length by continuously adding the leftmost bit to the left until the length is reached. 
    /// </summary>
    private static BitArray SignExtend(BitArray value, int size)
    {
        var result = new BitArray(size);

        //Get top bit of value
        var topBit = value[0];

        var startOffset = size - value.Length;
        //Copy bottom n bits of value to result
        for (var i = startOffset; i < size; i++)
        {
            result[i] = value[i - startOffset];
        }

        //Populate remaining bits with top bit
        for (var i = 0; i < startOffset; i++)
        {
            result[i] = topBit;
        }

        return result;
    }

    private static BitArray Replicate(BitArray original, int desiredLength)
    {
        if (desiredLength % original.Length != 0)
            throw new("Desired length is not a multiple of the original length");

        var result = new BitArray(desiredLength);

        for (var i = 0; i < desiredLength; i += original.Length)
        {
            for (var j = 0; j < original.Length; j++)
            {
                result[i + j] = original[j];
            }
        }

        return result;
    }

    private static long BitsToLong(BitArray bits)
    {
        var result = 0L;
        for (var i = 0; i < bits.Count; i++)
        {
            if (bits[i])
            {
                result |= 1L << (bits.Count - 1 - i); //Bit shifting in c# sucks so we have to recalculate this for each i instead of just shifting it right per iteration
            }
        }

        return result;
    }

    public static ulong RotateRight(ulong original, int numBits, int shift)
    {
        var m = shift % numBits;

        var right = original >> m;
        var left = original << (numBits - m);
        
        // 确保左移结果不会超出numBits的范围
        var mask = numBits == 64 ? ulong.MaxValue : (1UL << numBits) - 1;
        
        return (right | left) & mask;
    }

    private static BitArray LongToBits(long value, int numBits)
    {
        var bits = new BitArray(numBits);
        var mask = 1L << (numBits - 1);
        for (var i = 0; i < numBits; i++)
        {
            var isBitSet = (value & mask) != 0;
            mask >>= 1;
            bits[i] = isBitSet;
        }

        return bits;
    }

    public static int HighestSetBit(long value, int numBits)
    {
        return HighestSetBit(LongToBits(value, numBits));
    } 
    
    private static int HighestSetBit(BitArray bits)
    {
        for (var i = 0; i < bits.Length; i++)
        {
            if (bits.Get(i))
            {
                //Big endian -> little endian, then 0-indexed
                return (bits.Length - i) - 1;
            }
        }

        return 0;
    }

    public static long SignExtend(long original, int originalSizeBits, int newSizeBits)
    {
        var originalBits = LongToBits(original, originalSizeBits);
        var extendedBits = SignExtend(originalBits, newSizeBits);

        return BitsToLong(extendedBits);
    }

    public static int CorrectSignBit(uint original, int originalSizeBits)
    {
        var topBitMask = 1 << (originalSizeBits - 1);

        //Get top bit of value
        var topBit = (original & topBitMask) != 0;

        if (!topBit)
            return (int)original;

        //Negative - get remainder, and flip all bits, then subtract from -1
        //This means all bits set => -1 - 0 = -1
        //All bits clear (except sign bit) => -1 - ((2^originalSizeBits)-1) = -(2^originalSizeBits)
        var remainder = (int)original & (topBitMask - 1);

        return -1 - (~remainder & (topBitMask - 1));
    }

    public static ulong ApplyShift(ulong original, Arm64ShiftType type, int numBits, int amount)
    {
        return type switch
        {
            Arm64ShiftType.LSL => original << amount,
            Arm64ShiftType.LSR => original >> amount,
            Arm64ShiftType.ASR => (uint)((int)original >> amount),
            Arm64ShiftType.ROR => RotateRight(original, numBits, amount),
            _ => throw new ArgumentException("Unknown shift type")
        };
    }

    public static (long, long) DecodeBitMasks(bool nFlag, int desiredSize, byte imms, byte immr, bool immediate)
    {
        //imms and immr are actually 6 bits not 8.

        var combined = (short)((nFlag ? 1 << 6 : 0) | (~imms & 0b11_1111));
        var len = HighestSetBit(combined, 12);

        if (len < 1)
            throw new Arm64UndefinedInstructionException("DecodeBitMasks: highestBit < 1");

        // 计算element size
        var esize = 1 << len;
        
        if (esize > desiredSize)
        {
            throw new Arm64UndefinedInstructionException("DecodeBitMasks: (1 << len) > desiredSize");
        }

        var levels = (1 << len) - 1;

        var s = imms & levels;
        var r = immr & levels;
        var diff = s - r;

        var d = diff & ((1 << (len - 1)) - 1); //UInt(diff<len-1:0>)
        
        // 计算wElem和tElem
        long wElem = (1L << (s + 1)) - 1;
        long tElem = (1L << (d + 1)) - 1;
        
        // 创建在esize范围内的位模式，然后旋转
        var maskedWElem = esize == 64 ? wElem : wElem & ((1L << esize) - 1);
        
        ulong rotatedWElem = RotateRight((ulong)maskedWElem, esize, (int)r);
        
        // 使用原始的esize位模式，而不是旋转后的64位值
        BitArray rotatedBits = LongToBits(maskedWElem, esize); // 使用原始的maskedWElem
        RotateRightInPlace(rotatedBits, (int)r); // 在位数组上直接进行旋转
        
        BitArray wMask = Replicate(rotatedBits, desiredSize);
        
        BitArray tMask = Replicate(LongToBits(tElem, esize), desiredSize);

        return (BitsToLong(wMask), BitsToLong(tMask));
    }

    /// <summary>
    /// Expands the immediate value used in Advanced SIMD instructions.
    /// </summary>
    /// <param name="op">The op flag from the instruction</param>
    /// <param name="cmode">The 4-bit cmode field from the instruction</param>
    /// <param name="imm">The 8-bit immediate value as encoded in the instruction as a:b:c:d:e:f:g:h</param>
    public static ulong AdvancedSimdExpandImmediate(bool op, byte cmode, byte imm)
    {
        switch (cmode >> 1)
        {
            case 0b000:
            {
                // (Zeroes(24):imm8) twice
                var tmp = (uint)imm;
                return tmp & (ulong)tmp << 32;
            }
            case 0b001:
            {
                // (Zeroes(16):imm8:Zeroes(8)) twice
                var tmp = (uint)imm << 8;
                return tmp & (ulong)tmp << 32;
            }
            case 0b010:
            {
                // (Zeroes(8):imm8:Zeroes(16)) twice
                var tmp = (uint)imm << 16;
                return tmp & (ulong)tmp << 32;
            }
            case 0b011:
            {
                // (imm8:Zeroes(24)) twice
                var tmp = (uint)imm << 24;
                return tmp & (ulong)tmp << 32;
            }
            case 0b100:
            {
                // (Zeroes(8):imm8) four times
                var tmp = (ushort)imm;
                return tmp & (ulong)tmp << 16 & (ulong)tmp << 32 & (ulong)tmp << 48;
            }
            case 0b101:
            {
                // (imm8:Zeroes(8)) four times
                var tmp = (ushort)(imm << 8);
                return tmp & (ulong)tmp << 16 & (ulong)tmp << 32 & (ulong)tmp << 48;
            }
            case 0b110:
            {
                //Check low bit of cmode
                if ((cmode & 1) == 0)
                {
                    // (Zeroes(16):imm8:Ones(8)) twice
                    var tmp = (uint)imm << 8 | 0xFF;
                    return tmp & (ulong)tmp << 32;
                }

                // (Zeroes(8):imm8:Ones(16)) twice
                var tmp2 = (uint)imm << 16 | 0xFFFF;
                return tmp2 & (ulong)tmp2 << 32;
            }
            case 0b111:
            {
                var cmodeLow = (cmode & 1) == 1;
                if (!cmodeLow && !op)
                {
                    // (imm8) eight times
                    return imm & (ulong)imm << 8 & (ulong)imm << 16 & (ulong)imm << 24 & (ulong)imm << 32 & (ulong)imm << 40 & (ulong)imm << 48 & (ulong)imm << 56;
                }

                if (!cmodeLow && op)
                {
                    // for each of the 8 bits in the imm, repeat that bit 8 times, then concatenate the results
                    var tmp = 0ul;
                    for (var i = 0; i < 8; i++)
                    {
                        var bit = ((imm >> i) & 1) == 1;
                        tmp |= (ulong)(bit ? 0xFF : 0) << (i * 8);
                    }

                    return tmp;
                }

                // given that imm8 is abcdefgh, and uppercasing a letter inverts it, create aBbbbbbcdefgh (13 bits)
                var b = (imm & 0b0100_0000U) >> 6;
                var a = (imm & 0b1000_0000U) >> 7;
                var notB = b == 0 ? 1U : 0U;
                var cdefgh = imm & 0b0011_1111U;
                var bbbbb = b << 4 | b << 3 | b << 2 | b << 1 | b;
                var bitString = (a << 12) | (notB << 11) | (bbbbb << 6) | cdefgh; //aBbbbbbcdefgh

                if (cmodeLow && !op)
                {
                    //add 19 0s, then repeat it twice
                    bitString <<= 19; //append 19 0s
                    return bitString & (ulong)bitString << 32; //repeat twice
                }

                //last mode (cmodeLow && op): modify bitString a bit by inserting 3*b between b and c to make it 16-bit, then append 48 0s
                bitString = bitString >> 6 //discard cdefgh
                            << 3 //make room for 3*b
                            | (b << 2) | (b << 1) | b //insert 3*b
                            << 6 //make room for cdefgh
                            | cdefgh; //append cdefgh

                return (ulong)bitString << 48; //append 48 0s
            }
            default:
                throw new ArgumentException(nameof(cmode));
        }
    }

    public static double DecodeFPImm(uint pType, uint imm8)
    {
        //pType: 00 = 32-bit, 01 = 64-bit, 10 = 16-bit

        var n = pType switch
        {
            0b00 => 32,
            0b01 => 64,
            0b10 => 16,
            _ => throw new("Invalid pType")
        };

        var e = pType switch
        {
            0b00 => 8,
            0b01 => 11,
            0b10 => 5,
            _ => throw new("Invalid pType")
        };

        var f = n - e - 1;
        var signBit = imm8.TestBit(7);
        var exp = (imm8.TestBit(6) ? 0UL : 1UL);
        exp <<= e - 1;
        //Repeat bit 6 (e - 3) times
        var bit = imm8 >> 6 & 1;
        for (var i = 0; i < e - 3; i++)
        {
            exp |= bit << (e - 2 - i);
        }

        //Finally add bits 5 and 4
        exp |= (imm8 & 0b0011_0000U) >> 4;

        var frac = imm8 & 0b0000_1111U;
        frac <<= f - 4; //Append f - 4 0s

        var resultBits = (signBit ? 1UL : 0UL) << (n - 1);
        resultBits |= (ulong)exp << f;
        resultBits |= frac;

        var bytes = BitConverter.GetBytes(resultBits);

        return n switch
        {
            16 => ToFloat16(bytes),
            32 => BitConverter.ToSingle(bytes, 0),
            64 => BitConverter.ToDouble(bytes, 0),
            _ => throw new("Impossible")
        };
    }

    private static double ToFloat16(byte[] bytes)
    {
        //TODO Validate - ARM apparently might have a non-standard fp16 format
#if NET6_0
        return (double)BitConverter.ToHalf(bytes);
#else
        var sign = bytes[0] >> 7;
        var exp = (bytes[0] >> 3) & 0b1111;
        var frac = (bytes[0] & 0b111) << 8 | bytes[1];

        if (exp == 0b1111)
        {
            if (frac == 0)
            {
                return sign == 1 ? double.NegativeInfinity : double.PositiveInfinity;
            }

            return double.NaN;
        }

        if (exp == 0)
        {
            if (frac == 0)
            {
                return sign == 1 ? -0.0 : 0.0;
            }

            //Denormalized
            var tmp = frac * Math.Pow(2, -14);
            return sign == 1 ? -tmp : tmp;
        }

        //Normalized
        var result = (1 + frac * Math.Pow(2, -10)) * Math.Pow(2, exp - 15);
        return sign == 1 ? -result : result;
#endif
    }

    private static void RotateRightInPlace(BitArray bits, int shiftAmount)
    {
        int length = bits.Length;
        if (length == 0 || shiftAmount == 0) return;
        
        shiftAmount %= length;
        if (shiftAmount == 0) return;
        
        // 创建临时数组存储原始值
        bool[] temp = new bool[length];
        for (int i = 0; i < length; i++)
        {
            temp[i] = bits[i];
        }
        
        // 执行右旋转
        for (int i = 0; i < length; i++)
        {
            int newIndex = (i + shiftAmount) % length;
            bits[newIndex] = temp[i];
        }
    }
}