namespace Disarm.InternalDisassembly;

//Advanced SIMD family where op0 is 01x1
internal static class Arm64ScalarAdvancedSimd
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op1 = (instruction >> 23) & 0b11; //Bits 23-24
        var op2 = (instruction >> 19) & 0b1111; //Bits 19-22
        var op3 = (instruction >> 10) & 0b1_1111_1111; //Bits 10-18

        if (op1 == 0 && (op2 >> 2) == 0 && op3.TestPattern(0b000100001, 0b1))
            return Copy(instruction);

        if (op1 is 0b10 or 0b11)
        {
            if (op3.TestBit(0))
            {
                if (op1.TestBit(0))
                    //Op1 11 and op3 ends with a 1
                    throw new Arm64UndefinedInstructionException("Advanced SIMD (scalar): Unallocated");

                return ShiftByImmediate(instruction);
            }

            //Scalar x indexed element
            return ScalarXIndexedElement(instruction);
        }

        //This leaves the largest group, op1 == 0b0x
        //Switch by op2 first, where we can:

        if (op2 == 0b1111)
        {
            if (!op3.TestPattern(0b110000011, 0b10))
                throw new Arm64UndefinedInstructionException("Advanced SIMD (scalar): Unallocated");

            return TwoRegisterMiscFp16(instruction);
        }

        if (op2.TestBit(2))
        {
            //x1xx
            //Check to exclude x100 and x110 first
            if (op2.TestPattern(0b0111, 0b0100) && op3.TestPattern(0b110000011, 0b10))
                return TwoRegisterMisc(instruction);

            if (op2.TestPattern(0b0111, 0b0110) && op3.TestPattern(0b110000011, 0b10))
                return Pairwise(instruction);

            //Remaining x1xx
            if (op3.TestPattern(0b11, 0))
                return ThreeDifferent(instruction);

            if (op3.TestBit(0))
                return ThreeSame(instruction);

            throw new Arm64UndefinedInstructionException($"Advanced SIMD (scalar): Unallocated x1xx family: op2 = 0x{op2:X2}, op3 = {op3:X3}");
        }

        if (op2.TestPattern(0b1100, 0b1000) && op3.TestPattern(0b000110001, 1))
            return ThreeSameFp16(instruction);

        if (op2.TestPattern(0b0100, 0) && op3.TestPattern(0b000100001))
            return ThreeSameExtra(instruction);

        throw new Arm64UndefinedInstructionException($"Advanced SIMD (scalar): Unallocated fall-through, op1 = 0x{op1:X2}, op2 = 0x{op2:X2}, op3 = {op3:X3}");
    }

    public static Arm64Instruction Copy(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarRegisterToRegister, 
        };
    }

    public static Arm64Instruction ShiftByImmediate(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath
        };
    }

    public static Arm64Instruction ScalarXIndexedElement(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
        };
    }

    public static Arm64Instruction TwoRegisterMiscFp16(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Unspecified, //Could be comparison, math, conversion, or general data processing
        };
    }

    public static Arm64Instruction TwoRegisterMisc(uint instruction)
    {
        var uFlag = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11; //Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; //Bits 12-16
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4

        var sz = size.TestBit(0);
        
        //This is almost excessively miscellaneous.
        //Almost everything here has to be handled case-by-case.

        Arm64Register baseReg;
        Arm64Mnemonic mnemonic;
        Arm64MnemonicCategory category;

        switch (opcode)
        {
            case 0b11101 when !uFlag && size is 0b00 or 0b01:
                baseReg = sz ? Arm64Register.D0 : Arm64Register.S0; //32 << sz
                mnemonic = Arm64Mnemonic.SCVTF;
                category = Arm64MnemonicCategory.SimdScalarConversion;
                break;
            default:
                return new()
                {
                    Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
                    MnemonicCategory = Arm64MnemonicCategory.Unspecified, 
                };
        }

        var regD = baseReg + rd;
        var regN = baseReg + rn;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = regD,
            Op1Reg = regN,
            MnemonicCategory = category,
        };
    }
    
    public static Arm64Instruction Pairwise(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath, 
        };
    }

    public static Arm64Instruction ThreeDifferent(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath, 
        };
    }

    public static Arm64Instruction ThreeSame(uint instruction)
    {
        var q = (instruction >> 30) & 1;
        var u = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11;
        var rm = (int)(instruction >> 16) & 0b1_1111;
        var opcode = (instruction >> 11) & 0b1_1111;
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rd = (int)instruction & 0b1_1111;

        Arm64ArrangementSpecifier arrangement;

        if (opcode == 0b00011) // AND or BIC or ORR or ORN or EOR or BSL or BIT or BIF
        {
            arrangement = q switch
            {
                0 => Arm64ArrangementSpecifier.EightB,
                1 => Arm64ArrangementSpecifier.SixteenB,
                _ => throw new ArgumentOutOfRangeException()
            };
        }
        else if (opcode is >= 0b11000 and <= 0b11111)
        {
            arrangement = (instruction.TestBit(22) ? 1 : 0, q) switch
            {
                (0, 0) => Arm64ArrangementSpecifier.TwoS,
                (0, 1) => Arm64ArrangementSpecifier.FourS,
                (1, 1) => Arm64ArrangementSpecifier.TwoD,
                _ => throw new Arm64UndefinedInstructionException("RESERVED")
            };
        }
        else
        {
            arrangement = (size, q) switch
            {
                (0b00, 0) => Arm64ArrangementSpecifier.EightB,
                (0b00, 1) => Arm64ArrangementSpecifier.SixteenB,
                (0b01, 0) => Arm64ArrangementSpecifier.FourH,
                (0b01, 1) => Arm64ArrangementSpecifier.EightH,
                (0b10, 0) => Arm64ArrangementSpecifier.TwoS,
                (0b10, 1) => Arm64ArrangementSpecifier.FourS,
                _ => throw new Arm64UndefinedInstructionException("RESERVED")
            };
        }
        
        return new()
        {
            Mnemonic = u switch
            {
                false => opcode switch
                {
                    0b00000 => Arm64Mnemonic.SHADD,
                    0b00001 => Arm64Mnemonic.SQADD,
                    0b00010 => Arm64Mnemonic.SRHADD,
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
                    0b11000 when size is 0 or 1 => Arm64Mnemonic.FMAXNM, // other arrangment
                    0b11001 when size is 0 or 1 => Arm64Mnemonic.FMLA,
                    0b11010 when size is 0 or 1 => Arm64Mnemonic.FADD,
                    0b11011 when size is 0 or 1 => Arm64Mnemonic.FMULX,
                    0b11100 when size is 0 or 1 => Arm64Mnemonic.FCMEQ,
                    0b11110 when size is 0 or 1 => Arm64Mnemonic.FMAX,
                    0b11111 when size is 0 or 1 => Arm64Mnemonic.FRECPS,
                    0b00011 when size is 0 => Arm64Mnemonic.AND, // again other arrangment
                    // 0b11101 when size is 0 => Arm64Mnemonic.FMLAL, too hard // again other arrangment
                    0b00011 when size is 1 => Arm64Mnemonic.BIC, // again other arrangment...
                    0b11000 when size is 2 or 3 => Arm64Mnemonic.FMINNM,
                    0b11001 when size is 2 or 3 => Arm64Mnemonic.FMLS,
                    0b11010 when size is 2 or 3 => Arm64Mnemonic.FSUB,
                    0b11110 when size is 2 or 3 => Arm64Mnemonic.FMIN,
                    0b11111 when size is 2 or 3 => Arm64Mnemonic.FRSORTS,
                    0b00011 when size is 2 => Arm64Mnemonic.ORR,
                    //0b11101 when size is 2 => Arm64Mnemonic.FMLSL, too hard
                    0b00011 when size is 3 => Arm64Mnemonic.ORN, 
                    _ => throw new Arm64UndefinedInstructionException("Unallocated or unimplemented")
                },
                true => opcode switch
                {
                    0b00000 => Arm64Mnemonic.UHADD,
                    0b00001 => Arm64Mnemonic.UQADD,
                    0b00010 => Arm64Mnemonic.URHADD,
                    0b00100 => Arm64Mnemonic.UHSUB,
                    0b00101 => Arm64Mnemonic.UQSUB,
                    0b00110 => Arm64Mnemonic.CMHL,
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
                    0b10001 => Arm64Mnemonic.CMEO,
                    0b10010 => Arm64Mnemonic.MLS,
                    0b10011 => Arm64Mnemonic.PMUL,
                    0b10100 => Arm64Mnemonic.UMAXP,
                    0b10101 => Arm64Mnemonic.UMINP,
                    0b10110 => Arm64Mnemonic.SQRDMULH,
                    0b11000 when size is 0 or 1 => Arm64Mnemonic.FMAXNMP,
                    0b11010 when size is 0 or 1 => Arm64Mnemonic.FADDP,
                    0b11011 when size is 0 or 1 => Arm64Mnemonic.FMUL,
                    0b11100 when size is 0 or 1 => Arm64Mnemonic.FCMGE,
                    0b11101 when size is 0 or 1 => Arm64Mnemonic.FACGE,
                    0b11110 when size is 0 or 1 => Arm64Mnemonic.FMAXP,
                    0b11111 when size is 0 or 1 => Arm64Mnemonic.FDIV,
                    0b00011 when size is 0 => Arm64Mnemonic.EOR,
                    //0b11001 when size is 0 => Arm64Mnemonic.FMLAL2,
                    0b00011 when size is 1 => Arm64Mnemonic.BSL,
                    0b11000 when size is 2 or 3 => Arm64Mnemonic.FABD,
                    0b11100 when size is 2 or 3 => Arm64Mnemonic.FCMGT,
                    0b11101 when size is 2 or 3 => Arm64Mnemonic.FACGT,
                    0b11110 when size is 2 or 3 => Arm64Mnemonic.FMINP,
                    0b00011 when size is 2 => Arm64Mnemonic.BIT,
                    0b00011 when size is 3 => Arm64Mnemonic.BIF,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated or unimplemented")
                }
            },
            MnemonicCategory = Arm64MnemonicCategory.Unspecified, // TODO Could be comparison or math
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Arrangement = arrangement,
            Op1Arrangement = arrangement,
            Op2Arrangement = arrangement,
            Op0Reg = Arm64Register.V0 + rd,
            Op1Reg = Arm64Register.V0 + rn,
            Op2Reg = Arm64Register.V0 + rm,
        };
    }

    public static Arm64Instruction ThreeSameFp16(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Unspecified, //Scalar or math 
        };
    }

    public static Arm64Instruction ThreeSameExtra(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
        };
    }
}
