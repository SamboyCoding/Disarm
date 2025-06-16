namespace Disarm.InternalDisassembly;

internal static class Arm64NonScalarAdvancedSimd
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op0 = (instruction >> 28) & 0b1111;
        var op1 = (instruction >> 23) & 0b11;
        var op2 = (instruction >> 19) & 0b1111;
        var op3 = (instruction >> 10) & 0b1_1111_1111;

        var op1Hi = (op1 >> 1) == 1;
        var op2UpperHalf = op2 >> 2;
        var op3Lo = (op3 & 1) == 1;

        if (op1 == 0b11)
            return AdvancedSimdVectorXIndexedElement(instruction);

        //Handle the couple of cases where op1 is not simply 0b0x
        if (op1 == 0b10)
            return op3Lo
                ? op2 == 0 ? AdvancedSimdModifiedImmediate(instruction) : AdvancedSimdShiftByImmediate(instruction)
                : AdvancedSimdVectorXIndexedElement(instruction);

        if (op1 == 0 && op2UpperHalf == 0 && (op3 & 0b100001) == 1)
            return AdvancedSimdCopy(instruction);

        if ((op0 & 0b1011) == 0 && !op1Hi && (op2UpperHalf & 1) == 0)
        {
            var test = op3 & 0b100011;
            if (test == 0)
                return AdvancedSimdTableLookup(instruction);
            if (test == 0b10)
                return AdvancedSimdPermute(instruction);
        }

        if ((op0 & 0b1011) == 0b10 && !op1Hi && (op2UpperHalf & 1) == 0)
        {
            if ((op3 & 0b100001) == 0)
                return AdvancedSimdExtract(instruction);
        }

        if (op1 == 0 && op2UpperHalf == 0 && (op3 & 0b100001) == 1)
            return AdvancedSimdCopy(instruction);

        //Ok, now all the remaining define op0 as 0xx0 and op1 as 0x so there is no point checking either

        if (op2UpperHalf == 0b10 && (op3 & 0b110001) == 1)
            return AdvancedSimdThreeSameFp16(instruction);

        if (op2 == 0b1111 && (op3 & 0b1_1000_0011) == 0b10)
            return AdvancedSimdTwoRegisterMiscFp16(instruction);

        if ((op2UpperHalf & 1) == 0 && (op3 & 0b100001) == 0b100001)
            return AdvancedSimdThreeRegExtension(instruction);

        if (op2 is 0b0100 or 0b1100 && (op3 & 0b110000011) == 0b10)
            return AdvancedSimdTwoRegisterMisc(instruction);

        if (op2 is 0b0110 or 0b1110 && (op3 & 0b110000011) == 0b10)
            return AdvancedSimdAcrossLanes(instruction);

        if ((op2UpperHalf & 1) == 1)
        {
            if ((op3 & 0b11) == 0)
                return AdvancedSimdThreeDifferent(instruction);

            if (op3Lo)
                return AdvancedSimdThreeSame(instruction);
        }

        throw new Arm64UndefinedInstructionException($"Advanced SIMD instruction (non-scalar): op0: {op0}, op1: {op1}, op2: {op2}, op3: {op3}");
    }

    private static Arm64Instruction AdvancedSimdModifiedImmediate(uint instruction)
    {
        //Let's play the alphabet game I guess
        var qFlag = instruction.TestBit(30);
        var op = instruction.TestBit(29);
        var abc = (instruction >> 16) & 0b111;
        var cmode = (instruction >> 12) & 0b1111;
        var o2 = instruction.TestBit(11);
        var defgh = (instruction >> 5) & 0b1_1111;
        var rd = (int)instruction & 0b1_1111;

        var immediate = (long) (abc << 5 | defgh);

        //o2 is basically only valid when paired with !op and cmode == 1111 in which case it indicates a variant of fmov
        //conversely, if op is set and cmode is 1111 then this is only valid if o2 is set.

        if (op && o2)
            throw new Arm64UndefinedInstructionException("Advanced SIMD: modified immediate: op == 1 and o2 == 1");

        if (!qFlag && op && cmode == 0b1111 && !o2)
            throw new Arm64UndefinedInstructionException("Advanced SIMD: modified immediate: q == 0, op == 1, cmode == 1111 and o2 == 0");

        if (!op && o2 && !cmode.TestBit(3))
            throw new Arm64UndefinedInstructionException("Advanced SIMD: modified immediate: op == 0, o2 == 1 and high bit of cmode not set");

        if (!op && o2 && cmode.TestPattern(0b1100, 0b1000))
            throw new Arm64UndefinedInstructionException("Advanced SIMD: modified immediate: op == 0, o2 == 1 and cmode matches 10xx");

        if (!op && o2 && cmode.TestPattern(0b1110, 0b1100))
            throw new Arm64UndefinedInstructionException("Advanced SIMD: modified immediate: op == 0, o2 == 1 and cmode matches 110x");

        //That's all the undefined cases, now for the actual decoding
        //There's only really 5 different mnemonics (movi, orr, fmov, mvni, bic) but they seem to follow no pattern
        //for movi, op indicates shifted (0) vs not shifted (1)
        //when not shifted, q indicates scalar (0) vs vector (1)
        //mvni is always shifted

        //easiest is just to brute force this to be honest

        Arm64ArrangementSpecifier arrangement;

        if (cmode == 0b1111)
        {
            //Some variant of FMOV
            //Either:
            //  op         => (vector, imm), double precision
            //  !op && !o2 => (vector, imm), single precision
            //  !op && o2  => (vector, imm), half precision

            arrangement = op
                ? Arm64ArrangementSpecifier.TwoD //Double precision
                : o2
                    ? qFlag ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH //Half precision
                    : qFlag
                        ? Arm64ArrangementSpecifier.FourS
                        : Arm64ArrangementSpecifier.TwoS; //Single precision

            var convertedImmediate = Arm64CommonUtils.AdvancedSimdExpandImmediate(op, (byte)cmode, (byte) immediate);
            
            return new()
            {
                Mnemonic = Arm64Mnemonic.FMOV,
                Op0Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.V0 + rd,
                Op0Arrangement = arrangement,
                Op1Kind = Arm64OperandKind.Immediate,
                Op1Imm = (long)convertedImmediate,
                MnemonicCategory = Arm64MnemonicCategory.SimdConstantToRegister,
            };
        }

        Arm64Mnemonic mnemonic;
        int shiftAmount;
        var baseReg = Arm64Register.V0;

        if (!op)
        {
            //movi
            if (cmode.TestPattern(0b1001, 0))
                //32-bit shifted imm
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MOVI, qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS, 8 * (int) ((cmode >> 1) & 0b11)); //0/8/16/24
            else if (cmode.TestPattern(0b1101, 0b1000))
                //16-bit shifted imm
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MOVI, qFlag ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH, cmode.TestBit(1) ? 8 : 0);
            else if (cmode.TestPattern(0b1110, 0b1100))
                //32-bit shifting ones
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MOVI, qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS, cmode.TestBit(0) ? 16 : 8);
            else if (cmode == 0b1110)
                //8-bit
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MOVI, qFlag ? Arm64ArrangementSpecifier.SixteenB : Arm64ArrangementSpecifier.EightB, 0);
            //orr
            else if (cmode.TestPattern(0b1001, 0b0001))
                //32-bit
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.ORR, qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS, 8 * (int) ((cmode >> 1) & 0b11)); //0/8/16/24
            else if (cmode.TestPattern(0b1101, 0b1001))
                //16-bit
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.ORR, qFlag ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH, cmode.TestBit(1) ? 8 : 0);
            else
                throw new("Impossible cmode");
        }
        else
        {
            //mvni
            if (cmode.TestPattern(0b1001, 0))
                //32-bit shifted imm
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MVNI, qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS, 8 * (int) ((cmode >> 1) & 0b11)); //0/8/16/24
            else if (cmode.TestPattern(0b1101, 0b1000))
                //16-bit shifted imm
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MVNI, qFlag ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH, cmode.TestBit(1) ? 8 : 0);
            else if (cmode.TestPattern(0b1110, 0b1100))
                //32-bit shifting ones
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MVNI, qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS, cmode.TestBit(0) ? 16 : 8);
            //bic
            else if (cmode.TestPattern(0b1001, 0b0001))
                //32-bit
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.BIC, qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS, 8 * (int) ((cmode >> 1) & 0b11)); //0/8/16/24
            else if (cmode.TestPattern(0b1101, 0b1001))
                //16-bit
                (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.BIC, qFlag ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH, cmode.TestBit(1) ? 8 : 0);
            //movi
            else if (cmode == 0b1110)
            {
                immediate = (long) Arm64CommonUtils.AdvancedSimdExpandImmediate(op, (byte)cmode, (byte) immediate);
                if (qFlag)
                    (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MOVI, Arm64ArrangementSpecifier.TwoD, 0);
                else
                {
                    //64-bit scalar
                    baseReg = Arm64Register.D0;
                    (mnemonic, arrangement, shiftAmount) = (Arm64Mnemonic.MOVI, Arm64ArrangementSpecifier.None, 0);
                }
            }
            else
                throw new("Impossible cmode");
        }

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = baseReg + rd,
            Op0Arrangement = arrangement,
            Op1Kind = Arm64OperandKind.Immediate,
            Op1Imm = immediate,
            Op1ShiftType = shiftAmount > 0 ? Arm64ShiftType.LSL : Arm64ShiftType.NONE,
            Op2Kind = Arm64OperandKind.None,
            Op2Imm = 0,
            Op2ShiftType = Arm64ShiftType.NONE,
            MemExtendOrShiftAmount = shiftAmount,
            MnemonicCategory = Arm64MnemonicCategory.SimdConstantToRegister,
        };
    }

    private static Arm64Instruction AdvancedSimdShiftByImmediate(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath,
        };
    }

    private static Arm64Instruction AdvancedSimdVectorXIndexedElement(uint instruction)
    {
        var q = instruction.TestBit(30); // Bit 30
        var u = instruction.TestBit(29); // Bit 29
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var l = instruction.TestBit(21); // Bit 21
        var m = instruction.TestBit(20); // Bit 20
        var rm = (int)(instruction >> 16) & 0b1111; // Bits 16-19
        var opcode = (instruction >> 12) & 0b1111; // Bits 12-15
        var h = instruction.TestBit(11); // Bit 11
        var rn = (int)(instruction >> 5) & 0b1_1111; // Bits 5-9
        var rd = (int)instruction & 0b1_1111; // Bits 0-4

        // Determine mnemonic based on U and opcode
        Arm64Mnemonic mnemonic;
        if (u)
        {
            mnemonic = opcode switch
            {
                0b1001 when size != 0b01 => Arm64Mnemonic.FMULX,
                0b0010 => Arm64Mnemonic.UMLAL,
                0b0110 => Arm64Mnemonic.UMLSL,
                0b1010 => Arm64Mnemonic.UMULL,
                0b1101 => Arm64Mnemonic.SQRDMLAH,
                0b1111 => Arm64Mnemonic.SQRDMLSH,
                _ => throw new Arm64UndefinedInstructionException("AdvancedSimdVectorXIndexedElement: Unallocated U=1 opcode")
            };
        }
        else
        {
            mnemonic = opcode switch
            {
                0b0001 when size != 0b01 => Arm64Mnemonic.FMLA,
                0b0101 when size != 0b01 => Arm64Mnemonic.FMLS,
                0b1001 when size != 0b01 => Arm64Mnemonic.FMUL,
                0b0010 => Arm64Mnemonic.SMLAL,
                0b0110 => Arm64Mnemonic.SMLSL,
                0b1010 => Arm64Mnemonic.SMULL,
                0b0011 => Arm64Mnemonic.SQDMLAL,
                0b0111 => Arm64Mnemonic.SQDMLSL,
                0b1011 => Arm64Mnemonic.SQDMULL,
                0b1100 => Arm64Mnemonic.SQDMULH,
                0b1101 => Arm64Mnemonic.SQRDMULH,
                _ => throw new Arm64UndefinedInstructionException("AdvancedSimdVectorXIndexedElement: Unallocated U=0 opcode")
            };
        }

        var result = new Arm64Instruction()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.VectorRegisterElement,
        };

        // Set up operands based on instruction type
        if (mnemonic is Arm64Mnemonic.FMLA or Arm64Mnemonic.FMLS or Arm64Mnemonic.FMUL or Arm64Mnemonic.FMULX)
        {
            // Floating-point instructions
            var arrangement = size switch
            {
                0b00 => q ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH, // FP16
                0b10 => q ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS,   // Single
                0b11 => q ? Arm64ArrangementSpecifier.TwoD : throw new Arm64UndefinedInstructionException("Reserved"), // Double
                _ => throw new Arm64UndefinedInstructionException("Reserved size for FP")
            };

            var elementWidth = size switch
            {
                0b00 => Arm64VectorElementWidth.H,
                0b10 => Arm64VectorElementWidth.S,
                0b11 => Arm64VectorElementWidth.D,
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            };

            var elementIndex = size switch
            {
                0b00 => (h ? 4 : 0) | (l ? 2 : 0) | (m ? 1 : 0), // H:L:M for FP16
                0b10 => (h ? 2 : 0) | (l ? 1 : 0),               // H:L for Single
                0b11 => h ? 1 : 0,                               // H for Double
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            };

            result = result with
            {
                Op0Reg = Arm64Register.V0 + rd,
                Op0Arrangement = arrangement,
                Op1Reg = Arm64Register.V0 + rn,
                Op1Arrangement = arrangement,
                Op2Reg = Arm64Register.V0 + (rm | (m ? 16 : 0)),
                Op2VectorElement = new Arm64VectorElement(elementWidth, elementIndex)
            };
        }
        else
        {
            // Integer instructions - these have different source and destination arrangements
            var srcArrangement = size switch
            {
                0b01 => q ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH,
                0b10 => q ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS,
                _ => throw new Arm64UndefinedInstructionException("Reserved size for integer")
            };

            var dstArrangement = size switch
            {
                0b01 => q ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS,
                0b10 => q ? Arm64ArrangementSpecifier.TwoD : Arm64ArrangementSpecifier.None,
                _ => throw new Arm64UndefinedInstructionException("Reserved size for integer")
            };

            var elementWidth = size switch
            {
                0b01 => Arm64VectorElementWidth.H,
                0b10 => Arm64VectorElementWidth.S,
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            };

            var elementIndex = size switch
            {
                0b01 => (h ? 4 : 0) | (l ? 2 : 0) | (m ? 1 : 0), // H:L:M for 16-bit
                0b10 => (h ? 2 : 0) | (l ? 1 : 0),               // H:L for 32-bit
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            };

            // For SQDMULH and SQRDMULH, source and destination have same arrangement
            if (mnemonic is Arm64Mnemonic.SQDMULH or Arm64Mnemonic.SQRDMULH or Arm64Mnemonic.SQRDMLAH or Arm64Mnemonic.SQRDMLSH)
            {
                result = result with
                {
                    Op0Reg = Arm64Register.V0 + rd,
                    Op0Arrangement = srcArrangement,
                    Op1Reg = Arm64Register.V0 + rn,
                    Op1Arrangement = srcArrangement,
                    Op2Reg = Arm64Register.V0 + (rm | (m ? 16 : 0)),
                    Op2VectorElement = new Arm64VectorElement(elementWidth, elementIndex)
                };
            }
            else
            {
                // For other integer instructions, destination is wider
                result = result with
                {
                    Op0Reg = Arm64Register.V0 + rd,
                    Op0Arrangement = dstArrangement,
                    Op1Reg = Arm64Register.V0 + rn,
                    Op1Arrangement = srcArrangement,
                    Op2Reg = Arm64Register.V0 + (rm | (m ? 16 : 0)),
                    Op2VectorElement = new Arm64VectorElement(elementWidth, elementIndex)
                };
            }
        }

        return result;
    }

    private static Arm64Instruction AdvancedSimdCopy(uint instruction)
    {
        var qFlag = instruction.TestBit(30);
        var op = instruction.TestBit(29);
        var imm5 = ((instruction >> 16) & 0b1_1111);
        var imm4 = ((instruction >> 11) & 0b1111);
        var rn = (byte) ((instruction >> 5) & 0b1_1111);
        var rd = (byte) (instruction & 0b1_1111);
        
        if((imm5 & 0b1111) == 0)
            throw new Arm64UndefinedInstructionException("AdvancedSimdCopy: bottom 4 bits of imm5 must not be zero");
        
        if(op && !qFlag)
            throw new Arm64UndefinedInstructionException("AdvancedSimdCopy: op must be zero when qFlag is zero");

        if (op && qFlag)
        {
            //INS (element).
            Arm64VectorElementWidth width;
            uint index1;
            uint index2;
            
            if(imm5.TestBit(0))
                (width, index1, index2) = (Arm64VectorElementWidth.B, imm5 >> 1, imm4 & 0b1111);
            else if(imm5.TestBit(1))
                (width, index1, index2) = (Arm64VectorElementWidth.H, imm5 >> 2, (imm4 >> 1) & 0b111);
            else if(imm5.TestBit(2))
                (width, index1, index2) = (Arm64VectorElementWidth.S, imm5 >> 3, (imm4 >> 2) & 0b11);
            else
                (width, index1, index2) = (Arm64VectorElementWidth.D, imm5 >> 4, (imm4 >> 3) & 0b1);

            return new()
            {
                Mnemonic = Arm64Mnemonic.INS,
                Op0Kind = Arm64OperandKind.VectorRegisterElement,
                Op0Reg = Arm64Register.V0 + rd,
                Op0VectorElement = new Arm64VectorElement(width, (int)index1),
                Op1Kind = Arm64OperandKind.VectorRegisterElement,
                Op1Reg = Arm64Register.V0 + rn,
                Op1VectorElement = new Arm64VectorElement(width, (int)index2),
                MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister,
            };
        }

        var mnemonic = imm4 switch
        {
            0b0000 => Arm64Mnemonic.DUP, //DUP (element)
            0b0001 => Arm64Mnemonic.DUP, //DUP (general)
            0b0101 => Arm64Mnemonic.SMOV,
            0b0111 => Arm64Mnemonic.UMOV,
            0b0011 when qFlag => Arm64Mnemonic.INS, //INS (general)
            _ => throw new Arm64UndefinedInstructionException($"AdvancedSimdCopy: imm4 0x{imm4:X} is reserved")
        };

        if (mnemonic == Arm64Mnemonic.DUP && imm4 == 0b0000)
        {
            // DUP (element) - duplicate vector element to vector or scalar
            Arm64VectorElementWidth elementWidth;
            uint elementIndex;
            Arm64ArrangementSpecifier arrangement;
            
            if (imm5.TestBit(0))
            {
                // 8-bit elements
                elementWidth = Arm64VectorElementWidth.B;
                elementIndex = imm5 >> 1;
                arrangement = qFlag ? Arm64ArrangementSpecifier.SixteenB : Arm64ArrangementSpecifier.EightB;
            }
            else if (imm5.TestBit(1))
            {
                // 16-bit elements  
                elementWidth = Arm64VectorElementWidth.H;
                elementIndex = imm5 >> 2;
                arrangement = qFlag ? Arm64ArrangementSpecifier.EightH : Arm64ArrangementSpecifier.FourH;
            }
            else if (imm5.TestBit(2))
            {
                // 32-bit elements
                elementWidth = Arm64VectorElementWidth.S;
                elementIndex = imm5 >> 3;
                arrangement = qFlag ? Arm64ArrangementSpecifier.FourS : Arm64ArrangementSpecifier.TwoS;
            }
            else if (imm5.TestBit(3))
            {
                // 64-bit elements
                elementWidth = Arm64VectorElementWidth.D;
                elementIndex = imm5 >> 4;
                arrangement = qFlag ? Arm64ArrangementSpecifier.TwoD : throw new Arm64UndefinedInstructionException("DUP: 64-bit scalar not supported in this context");
            }
            else
            {
                throw new Arm64UndefinedInstructionException("DUP: invalid imm5 value");
            }

            return new()
            {
                Mnemonic = Arm64Mnemonic.DUP,
                Op0Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.V0 + rd,
                Op0Arrangement = arrangement,
                Op1Kind = Arm64OperandKind.VectorRegisterElement,
                Op1Reg = Arm64Register.V0 + rn,
                Op1VectorElement = new Arm64VectorElement(elementWidth, (int)elementIndex),
                MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister,
            };
        }

        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister, 
        };
    }

    private static Arm64Instruction AdvancedSimdTableLookup(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister, 
        };
    }

    private static Arm64Instruction AdvancedSimdPermute(uint instruction)
    {
        var q = instruction.TestBit(30);
        var size = (instruction >> 22) & 0b11;
        var rm = (int)(instruction >> 16) & 0b11111;
        var opcode = (instruction >> 12) & 0b111;
        var rn = (int)(instruction >> 5) & 0b11111;
        var rd = (int)instruction & 0b11111;

        // Determine mnemonic based on opcode
        Arm64Mnemonic mnemonic = opcode switch
        {
            0b001 => Arm64Mnemonic.UZP1,
            0b101 => Arm64Mnemonic.TRN1,
            0b011 => Arm64Mnemonic.ZIP1,
            0b000 => Arm64Mnemonic.UZP2,
            0b100 => Arm64Mnemonic.TRN2,
            0b010 => Arm64Mnemonic.ZIP2,
            _ => throw new Arm64UndefinedInstructionException($"AdvancedSimdPermute: Invalid opcode 0x{opcode:X}")
        };

        // Determine arrangement based on size and q
        Arm64ArrangementSpecifier arrangement = size switch
        {
            0b00 when q => Arm64ArrangementSpecifier.SixteenB,
            0b00 => Arm64ArrangementSpecifier.EightB,
            0b01 when q => Arm64ArrangementSpecifier.EightH,
            0b01 => Arm64ArrangementSpecifier.FourH,
            0b10 when q => Arm64ArrangementSpecifier.FourS,
            0b10 => Arm64ArrangementSpecifier.TwoS,
            0b11 when q => Arm64ArrangementSpecifier.TwoD,
            0b11 => throw new Arm64UndefinedInstructionException("AdvancedSimdPermute: size=11, q=0 is reserved"),
            _ => throw new("Impossible size")
        };

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rd,
            Op0Arrangement = arrangement,
            Op1Kind = Arm64OperandKind.Register,
            Op1Reg = Arm64Register.V0 + rn,
            Op1Arrangement = arrangement,
            Op2Kind = Arm64OperandKind.Register,
            Op2Reg = Arm64Register.V0 + rm,
            Op2Arrangement = arrangement,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath,
        };
    }

    private static Arm64Instruction AdvancedSimdExtract(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister, 
        };
    }

    private static Arm64Instruction AdvancedSimdThreeSameFp16(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath, 
        };
    }

    private static Arm64Instruction AdvancedSimdTwoRegisterMiscFp16(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Unspecified, //Could be convert to/from float, or fp comparison, or fp math
        };
    }

    private static Arm64Instruction AdvancedSimdThreeRegExtension(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath, 
        };
    }

    private static Arm64Instruction AdvancedSimdTwoRegisterMisc(uint instruction)
    {
        var q = instruction.TestBit(30);
        var u = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11;
        var opcode = (instruction >> 12) & 0b1_1111;
        var rn = (int)((instruction >> 5) & 0b1_1111);
        var rd = (int)(instruction & 0b1_1111);

        Arm64Mnemonic mnemonic;
        
        if (u)
        {
            mnemonic = opcode switch
            {
                0b00000 when size != 0b11 => Arm64Mnemonic.REV32,
                0b00001 when size is 0b00 or 0b01 => Arm64Mnemonic.REV16,
                0b00010 => Arm64Mnemonic.UADDLP,
                0b00011 => Arm64Mnemonic.USQADD,
                0b00100 => Arm64Mnemonic.CLZ,
                0b00101 => Arm64Mnemonic.CLZ,
                0b00111 => Arm64Mnemonic.SQNEG,
                0b01000 => Arm64Mnemonic.CMGE,
                0b01001 => Arm64Mnemonic.CMLE,
                0b01010 => Arm64Mnemonic.FCMGT,
                0b01011 => Arm64Mnemonic.FCMGE,
                0b10010 => Arm64Mnemonic.SQXTUN,
                0b10100 => Arm64Mnemonic.UQXTN,
                0b10110 when size != 0b11 => Arm64Mnemonic.FCVTXN,
                0b11000 when size != 0b11 => Arm64Mnemonic.FRINTA,
                0b11001 when size != 0b11 => Arm64Mnemonic.FRINTX,
                0b11010 when size != 0b11 => Arm64Mnemonic.FCVTNU,
                0b11011 when size != 0b11 => Arm64Mnemonic.FCVTMU,
                0b11100 when size != 0b11 => Arm64Mnemonic.FCVTAU,
                0b11101 when size != 0b11 => Arm64Mnemonic.UCVTF,
                0b11111 when size != 0b11 => Arm64Mnemonic.FRSQRTE,
                _ => throw new Arm64UndefinedInstructionException($"AdvancedSimdTwoRegisterMisc: U=1, opcode=0x{opcode:X}, size=0x{size:X}")
            };
        }
        else
        {
            mnemonic = opcode switch
            {
                0b00000 when size != 0b11 => Arm64Mnemonic.REV64,
                0b00001 when size is 0b00 or 0b01 => Arm64Mnemonic.REV32,
                0b00010 => Arm64Mnemonic.SADDLP,
                0b00011 => Arm64Mnemonic.SUQADD,
                0b00100 => Arm64Mnemonic.CLS,
                0b00101 when size is 0b00 => Arm64Mnemonic.CNT,
                0b00101 => throw new Arm64UndefinedInstructionException($"AdvancedSimdTwoRegisterMisc: U=0, opcode=0b00101, size=0x{size:X} (CNT only valid for size=0b00)"),
                0b00110 => Arm64Mnemonic.SADALP,
                0b00111 => Arm64Mnemonic.SQABS,
                0b01000 => Arm64Mnemonic.CMGT,
                0b01001 => Arm64Mnemonic.CMEQ,
                0b01010 => Arm64Mnemonic.CMLT,
                0b01011 => Arm64Mnemonic.ABS,
                0b10010 => Arm64Mnemonic.XTN,
                0b10100 => Arm64Mnemonic.SQXTN,
                0b10110 when size != 0b11 => Arm64Mnemonic.FCVTN,
                0b10111 when size != 0b11 => Arm64Mnemonic.FCVTL,
                0b11000 when size != 0b11 => Arm64Mnemonic.FRINTN,
                0b11001 when size != 0b11 => Arm64Mnemonic.FRINTM,
                0b11010 when size != 0b11 => Arm64Mnemonic.FCVTNS,
                0b11011 when size != 0b11 => Arm64Mnemonic.FCVTMS,
                0b11100 when size != 0b11 => Arm64Mnemonic.FCVTAS,
                0b11101 when size != 0b11 => Arm64Mnemonic.SCVTF,
                0b11111 when size != 0b11 => Arm64Mnemonic.FRECPE,
                _ => throw new Arm64UndefinedInstructionException($"AdvancedSimdTwoRegisterMisc: U=0, opcode=0x{opcode:X}, size=0x{size:X}")
            };
        }

        // Determine arrangement based on size and q
        Arm64ArrangementSpecifier arrangement = size switch
        {
            0b00 when q => Arm64ArrangementSpecifier.SixteenB,
            0b00 => Arm64ArrangementSpecifier.EightB,
            0b01 when q => Arm64ArrangementSpecifier.EightH,
            0b01 => Arm64ArrangementSpecifier.FourH,
            0b10 when q => Arm64ArrangementSpecifier.FourS,
            0b10 => Arm64ArrangementSpecifier.TwoS,
            0b11 when q => Arm64ArrangementSpecifier.TwoD,
            0b11 => Arm64ArrangementSpecifier.None, // Scalar D register
            _ => throw new("Impossible size")
        };

        var category = mnemonic switch
        {
            Arm64Mnemonic.CMGT or Arm64Mnemonic.CMEQ or Arm64Mnemonic.CMLT or 
            Arm64Mnemonic.CMGE or Arm64Mnemonic.CMLE or 
            Arm64Mnemonic.FCMGT or Arm64Mnemonic.FCMGE => Arm64MnemonicCategory.SimdComparison,
            _ => Arm64MnemonicCategory.SimdVectorMath,
        };

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rd,
            Op0Arrangement = arrangement,
            Op1Kind = Arm64OperandKind.Register,
            Op1Reg = Arm64Register.V0 + rn,
            Op1Arrangement = arrangement,
            MnemonicCategory = category,
        };
    }

    private static Arm64Instruction AdvancedSimdAcrossLanes(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath, 
        };
    }

    private static Arm64Instruction AdvancedSimdThreeDifferent(uint instruction)
    {
        var q = instruction.TestBit(30);
        var u = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11;
        var rm = (int)(instruction >> 16) & 0b1_1111;
        var opcode = (instruction >> 12) & 0b1111;
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rd = (int)instruction & 0b1_1111;

        if (opcode == 0b1111)
            throw new Arm64UndefinedInstructionException("AdvancedSimdThreeSame: opcode == 1111");

        if (size == 0b11)
            throw new Arm64UndefinedInstructionException("AdvancedSimdThreeSame: size = 11");

        Arm64Mnemonic mnemonic;
        if (u)
            mnemonic = opcode switch
            {
                0b0000 when q => Arm64Mnemonic.UADDL2,
                0b0000 => Arm64Mnemonic.UADDL,
                0b0001 when q => Arm64Mnemonic.UADDW2,
                0b0001 => Arm64Mnemonic.UADDW,
                0b0010 when q => Arm64Mnemonic.USUBL2,
                0b0010 => Arm64Mnemonic.USUBL,
                0b0011 when q => Arm64Mnemonic.USUBW2,
                0b0011 => Arm64Mnemonic.USUBW,
                0b0100 when q => Arm64Mnemonic.RADDHN2,
                0b0100 => Arm64Mnemonic.RADDHN,
                0b0101 when q => Arm64Mnemonic.UABAL2,
                0b0101 => Arm64Mnemonic.UABAL,
                0b0110 when q => Arm64Mnemonic.RSUBHN2,
                0b0110 => Arm64Mnemonic.RSUBHN,
                0b0111 when q => Arm64Mnemonic.UABDL2,
                0b0111 => Arm64Mnemonic.UABDL,
                0b1000 when q => Arm64Mnemonic.UMLAL2,
                0b1000 => Arm64Mnemonic.UMLAL,
                0b1001 => throw new Arm64UndefinedInstructionException("AdvancedSimdThreeSame: U && opcode == 1001"),
                0b1010 when q => Arm64Mnemonic.UMLSL2,
                0b1010 => Arm64Mnemonic.UMLSL,
                0b1011 => throw new Arm64UndefinedInstructionException("AdvancedSimdThreeSame: U && opcode == 1011"),
                0b1100 when q => Arm64Mnemonic.UMULL2,
                0b1100 => Arm64Mnemonic.UMULL,
                0b1101 => throw new Arm64UndefinedInstructionException("AdvancedSimdThreeSame: U && opcode == 1101"),
                0b1110 => throw new Arm64UndefinedInstructionException("AdvancedSimdThreeSame: U && opcode == 1110"),
                _ => throw new("Impossible opcode")
            };
        else
            mnemonic = opcode switch
            {
                0b0000 when q => Arm64Mnemonic.SADDL2,
                0b0000 => Arm64Mnemonic.SADDL,
                0b0001 when q => Arm64Mnemonic.SADDW2,
                0b0001 => Arm64Mnemonic.SADDW,
                0b0010 when q => Arm64Mnemonic.SSUBL2,
                0b0010 => Arm64Mnemonic.SSUBL,
                0b0011 when q => Arm64Mnemonic.SSUBW2,
                0b0011 => Arm64Mnemonic.SSUBW,
                0b0100 when q => Arm64Mnemonic.ADDHN2,
                0b0100 => Arm64Mnemonic.ADDHN,
                0b0101 when q => Arm64Mnemonic.SABAL2,
                0b0101 => Arm64Mnemonic.SABAL,
                0b0110 when q => Arm64Mnemonic.SUBHN2,
                0b0110 => Arm64Mnemonic.SUBHN,
                0b0111 when q => Arm64Mnemonic.SABDL2,
                0b0111 => Arm64Mnemonic.SABDL,
                0b1000 when q => Arm64Mnemonic.SMLAL2,
                0b1000 => Arm64Mnemonic.SMLAL,
                0b1001 when q => Arm64Mnemonic.SQDMLAL2,
                0b1001 => Arm64Mnemonic.SQDMLAL,
                0b1010 when q => Arm64Mnemonic.SMLSL2,
                0b1010 => Arm64Mnemonic.SMLSL,
                0b1011 when q => Arm64Mnemonic.SQDMLSL2,
                0b1011 => Arm64Mnemonic.SQDMLSL,
                0b1100 when q => Arm64Mnemonic.SMULL2,
                0b1100 => Arm64Mnemonic.SMULL,
                0b1101 when q => Arm64Mnemonic.SQDMULL2,
                0b1101 => Arm64Mnemonic.SQDMULL,
                0b1110 when q => Arm64Mnemonic.PMULL2,
                0b1110 => Arm64Mnemonic.PMULL,
                _ => throw new("Impossible opcode")
            };

        var baseReg = Arm64Register.V0;
        var sizeOne = size switch
        {
            0b00 => Arm64ArrangementSpecifier.EightH,
            0b01 => Arm64ArrangementSpecifier.FourS,
            0b10 => Arm64ArrangementSpecifier.TwoD,
            _ => throw new("Impossible size"),
        };

        var sizeTwo = size switch
        {
            0b00 when q => Arm64ArrangementSpecifier.EightB,
            0b00 => Arm64ArrangementSpecifier.SixteenB,
            0b01 when q => Arm64ArrangementSpecifier.FourH,
            0b01 => Arm64ArrangementSpecifier.EightH,
            0b10 when q => Arm64ArrangementSpecifier.TwoS,
            0b10 => Arm64ArrangementSpecifier.FourS,
            _ => throw new("Impossible size"),
        };

        return new Arm64Instruction()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = baseReg + rd,
            Op1Reg = baseReg + rn,
            Op2Reg = baseReg + rm,
            Op0Arrangement = sizeOne,
            Op1Arrangement = sizeTwo,
            Op2Arrangement = sizeTwo,
            MnemonicCategory = Arm64MnemonicCategory.SimdVectorMath,
        };
    }

    private static Arm64Instruction AdvancedSimdThreeSame(uint instruction)
    {
        var q = instruction.TestBit(30);
        var u = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11;
        var rm = (int)((instruction >> 16) & 0b1_1111);
        var opcode = (instruction >> 11) & 0b1_1111;
        var rn = (int)((instruction >> 5) & 0b1_1111);
        var rd = (int)(instruction & 0b1_1111);

        var sizeHi = size.TestBit(1);

        Arm64Mnemonic mnemonic;

        if (u)
            mnemonic = opcode switch
            {
                0b00000 => Arm64Mnemonic.UHADD,
                0b00001 => Arm64Mnemonic.UQADD,
                0b00010 => Arm64Mnemonic.URHADD,
                0b00011 when size is 0b00 => Arm64Mnemonic.EOR,
                0b00011 when size is 0b01 => Arm64Mnemonic.BSL,
                0b00011 when size is 0b10 => Arm64Mnemonic.BIT,
                0b00011 when size is 0b11 => Arm64Mnemonic.BIF,
                0b00100 => Arm64Mnemonic.UHSUB,
                0b00101 => Arm64Mnemonic.UQSUB,
                0b00110 => Arm64Mnemonic.CMHI,
                0b00111 => Arm64Mnemonic.CMHS,
                0b01000 => Arm64Mnemonic.USHL,
                0b01001 => Arm64Mnemonic.UQSHL,
                0b01010 => Arm64Mnemonic.URSHL,
                0b01011 => Arm64Mnemonic.UQRSHL,
                0b01100 => Arm64Mnemonic.UMAX,
                0b01101 => Arm64Mnemonic.UMIN,
                0b01110 => Arm64Mnemonic.UABD,
                0b01111 => Arm64Mnemonic.UABA,
                0b10000 => Arm64Mnemonic.SUB,
                0b10001 => Arm64Mnemonic.CMEQ,
                0b10010 => Arm64Mnemonic.MLS,
                0b10011 => Arm64Mnemonic.PMUL,
                0b10100 => Arm64Mnemonic.UMAXP,
                0b10101 => Arm64Mnemonic.UMINP,
                0b10110 => Arm64Mnemonic.SQRDMULH,
                0b10111 when size is 0b00 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b10111, size=0b00"),
                0b10111 when size is 0b01 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b10111, size=0b01"),
                0b10111 when size is 0b10 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b10111, size=0b10"),
                0b10111 when size is 0b11 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b10111, size=0b11"),
                0b11000 when !sizeHi => Arm64Mnemonic.FMAXNMP,
                0b11000 => Arm64Mnemonic.FMINNMP,
                0b11001 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b11001"),
                0b11010 when !sizeHi => Arm64Mnemonic.FADDP,
                0b11010 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b11010 with high size bit set"),
                0b11011 when !sizeHi => Arm64Mnemonic.FMUL,
                0b11011 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b11011 with high size bit set"),
                0b11100 when !sizeHi => Arm64Mnemonic.FCMGE,
                0b11100 => Arm64Mnemonic.FCMGT,
                0b11101 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b11101"),
                0b11110 when !sizeHi => Arm64Mnemonic.FMAXP,
                0b11110 => Arm64Mnemonic.FMINP,
                0b11111 when !sizeHi => Arm64Mnemonic.FDIV,
                0b11111 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: U=1, opcode=0b11111 with high size bit set"),
                _ => throw new("Impossible opcode")
            };
        else
            mnemonic = opcode switch
            {
                0b00000 => Arm64Mnemonic.SHADD,
                0b00001 => Arm64Mnemonic.SQADD,
                0b00010 => Arm64Mnemonic.SRHADD,
                0b00011 when size is 0b00 => Arm64Mnemonic.AND,
                0b00011 when size is 0b01 => Arm64Mnemonic.BIC,
                0b00011 when size is 0b10 => Arm64Mnemonic.ORR,
                0b00011 when size is 0b11 => Arm64Mnemonic.ORN,
                0b00100 => Arm64Mnemonic.SHSUB,
                0b00101 => Arm64Mnemonic.SQSUB,
                0b00110 => Arm64Mnemonic.CMGT,
                0b00111 => Arm64Mnemonic.CMGE,
                0b01000 => Arm64Mnemonic.SSHL,
                0b01001 => Arm64Mnemonic.SQSHL,
                0b01010 => Arm64Mnemonic.SRSHL,
                0b01011 => Arm64Mnemonic.SQRSHL,
                0b01100 => Arm64Mnemonic.SMAX,
                0b01101 => Arm64Mnemonic.SMIN,
                0b01110 => Arm64Mnemonic.SABD,
                0b01111 => Arm64Mnemonic.SABA,
                0b10000 => Arm64Mnemonic.ADD,
                0b10001 => Arm64Mnemonic.CMTST,
                0b10010 => Arm64Mnemonic.MLA,
                0b10011 => Arm64Mnemonic.MUL,
                0b10100 => Arm64Mnemonic.SMAXP,
                0b10101 => Arm64Mnemonic.SMINP,
                0b10110 => Arm64Mnemonic.SQDMULH,
                0b10111 => Arm64Mnemonic.ADDP,
                0b11000 when !sizeHi => Arm64Mnemonic.FMAXNM,
                0b11000 => Arm64Mnemonic.FMINNM,
                0b11001 when !sizeHi => Arm64Mnemonic.FMLA,
                0b11001 => Arm64Mnemonic.FMLS,
                0b11010 when !sizeHi => Arm64Mnemonic.FADD,
                0b11010 => Arm64Mnemonic.FSUB,
                0b11011 when !sizeHi => Arm64Mnemonic.FMULX,
                0b11011 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: opcode 0b11011 with high size bit set"),
                0b11100 when !sizeHi => Arm64Mnemonic.FCMEQ,
                0b11100 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: opcode 0b11100 with high size bit set"),
                0b11101 when size is 0b00 => Arm64Mnemonic.FMLAL, //TODO or FMLAL2
                0b11101 when size is 0b01 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: opcode 0b11101 with size 0b01"),
                0b11101 when size is 0b10 => Arm64Mnemonic.FMLSL, //TODO or FMLSL2
                0b11101 when size is 0b11 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: opcode 0b11101 with size 0b11"),
                0b11110 when !sizeHi => Arm64Mnemonic.FMAX,
                0b11110 => Arm64Mnemonic.FMIN,
                0b11111 when !sizeHi => Arm64Mnemonic.FRECPS,
                0b11111 => Arm64Mnemonic.FRSQRTS,
                _ => throw new("Impossible opcode")
            };

        var category = mnemonic switch
        {
            Arm64Mnemonic.CMGT or Arm64Mnemonic.CMGE or Arm64Mnemonic.CMTST or 
            Arm64Mnemonic.CMHI or Arm64Mnemonic.CMHS or Arm64Mnemonic.CMEQ or
            Arm64Mnemonic.FCMEQ or Arm64Mnemonic.FCMGE or Arm64Mnemonic.FCMGT => Arm64MnemonicCategory.SimdComparison,
            _ => Arm64MnemonicCategory.SimdVectorMath,
        };

        //Three groups of arrangements based on how much of size is used
        //If the top bit is specified (i.e. sizeHi used) then arrangement is a 2-bit field - lower bit of size : Q
        //If both bits are specified, arrangement is a 1-bit field - Q
        //If neither bit is specified, arrangement is a 3-bit field - size : Q

        Arm64ArrangementSpecifier arrangement;
        Arm64Register baseReg;

        if (mnemonic is Arm64Mnemonic.AND or Arm64Mnemonic.BIC or Arm64Mnemonic.ORR or Arm64Mnemonic.ORN or
                      Arm64Mnemonic.EOR or Arm64Mnemonic.BSL or Arm64Mnemonic.BIT or Arm64Mnemonic.BIF)
        {
            baseReg = Arm64Register.V0;
            arrangement = q ? Arm64ArrangementSpecifier.SixteenB : Arm64ArrangementSpecifier.EightB;
        }
        else if (opcode < 0b11000)
        {
            //"Simple" instructions 
            baseReg = Arm64Register.V0;

            //This logic should be ok though
            arrangement = size switch
            {
                0b00 when q => Arm64ArrangementSpecifier.SixteenB,
                0b00 => Arm64ArrangementSpecifier.EightB,
                0b01 when q => Arm64ArrangementSpecifier.EightH,
                0b01 => Arm64ArrangementSpecifier.FourH,
                0b10 when q => Arm64ArrangementSpecifier.FourS,
                0b10 => Arm64ArrangementSpecifier.TwoS,
                0b11 when q => Arm64ArrangementSpecifier.TwoD,
                0b11 => Arm64ArrangementSpecifier.None, // Scalar D register
                _ => throw new("Impossible size")
            };
        }
        else if (opcode == 0b11101)
        {
            throw new NotImplementedException();
        }
        else
        {
            //Uses the high bit of size, leaving only bit 22 as sz, and q
            var arrangementBits = (size & 0b1) << 1 | (uint)(q ? 1 : 0);

            arrangement = arrangementBits switch
            {
                0b00 => Arm64ArrangementSpecifier.TwoS,
                0b01 => Arm64ArrangementSpecifier.FourS,
                0b10 => throw new Arm64UndefinedInstructionException("Advanced SIMD three same: arrangement: sz = 1, Q = 0: reserved"),
                0b11 => Arm64ArrangementSpecifier.TwoD,
                _ => throw new("Impossible arrangement bits")
            };
            baseReg = Arm64Register.V0;
        }

        var regD = baseReg + rd;
        var regN = baseReg + rn;
        var regM = baseReg + rm;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Arrangement = arrangement,
            Op1Arrangement = arrangement,
            Op2Arrangement = arrangement,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            MnemonicCategory = category,
        };
    }
}
