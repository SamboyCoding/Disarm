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
        var u = instruction.TestBit(29);
        var immh = (instruction >> 19) & 0b1111; // Bits 19-22
        var imm = (instruction >> 16) & 0b111_1111; // Bits 16-22 : uint
        var opcode = (instruction >> 11) & 0b1_1111; // Bits 11-15
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4

        if (immh == 0)
            throw new Arm64UndefinedInstructionException("Unallocated");

        var esize = 8 << 3;
        
        var result = new Arm64Instruction()
        {
            Mnemonic = u switch
            {
                true => opcode switch
                {
                    0b00000 => Arm64Mnemonic.USHR,
                    0b00010 => Arm64Mnemonic.USRA,
                    0b00100 => Arm64Mnemonic.URSHR,
                    0b00110 => Arm64Mnemonic.URSRA,
                    0b01000 => Arm64Mnemonic.SRI,
                    0b01010 => Arm64Mnemonic.SLI,
                    0b01100 => Arm64Mnemonic.SQSHLU,
                    0b01110 => Arm64Mnemonic.UQSHL,
                    0b10000 => Arm64Mnemonic.SQSHRUN,
                    0b10001 => Arm64Mnemonic.SQRSHRUN,
                    0b10010 => Arm64Mnemonic.UQSHRN,
                    0b10011 => Arm64Mnemonic.UQRSHRN,
                    0b11100 => Arm64Mnemonic.UCVTF,
                    0b11111 => Arm64Mnemonic.FCVTZU,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                },
                false => opcode switch
                {
                    0b00000 => Arm64Mnemonic.SSHR,
                    0b00010 => Arm64Mnemonic.SSRA,
                    0b00100 => Arm64Mnemonic.SRSHR,
                    0b00110 => Arm64Mnemonic.SRSRA,
                    0b01010 => Arm64Mnemonic.SHL,
                    0b01110 => Arm64Mnemonic.SQSHL,
                    0b10010 => Arm64Mnemonic.SQSHRN,
                    0b10011 => Arm64Mnemonic.SQRSHRN,
                    0b11100 => Arm64Mnemonic.SCVTF,
                    0b11111 => Arm64Mnemonic.FCVTZS,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                }
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
        };
        
        Arm64Register width;

        switch (result.Mnemonic)
        {
            case Arm64Mnemonic.SSHR:
            case Arm64Mnemonic.SSRA:
            case Arm64Mnemonic.SRSHR:
            case Arm64Mnemonic.SRSRA:
            case Arm64Mnemonic.USHR:
            case Arm64Mnemonic.USRA:
            case Arm64Mnemonic.URSHR:
            case Arm64Mnemonic.URSRA:
            case Arm64Mnemonic.SRI:
                if ((immh & 0b1000) != 0b1000)
                    throw new Arm64UndefinedInstructionException("Reserved");
                width = Arm64Register.D0;
                result = result with
                {
                    Op0Reg = width + rd,
                    Op1Reg = width + rn,
                    Op2Imm =  (esize * 2) - imm
                };
                break;
            case Arm64Mnemonic.SHL:
            case Arm64Mnemonic.SLI:
                if ((immh & 0b1000) != 0b1000)
                    throw new Arm64UndefinedInstructionException("Reserved");
                width = Arm64Register.D0;
                result = result with
                {
                    Op0Reg = width + rd,
                    Op1Reg = width + rn,
                    Op2Imm = imm - esize
                };
                break;
            case Arm64Mnemonic.SQSHL:
            case Arm64Mnemonic.SQSHLU:
            case Arm64Mnemonic.UQSHL:
                esize = 8 << (int)(immh >> 3); // HighestSetBit(immh)
                width = immh switch
                {
                    0 => throw new Arm64UndefinedInstructionException("Reserved"),
                    0b0001 => Arm64Register.B0,
                    0b0010 or 0b0011 => Arm64Register.H0,
                    >= 0b0100 and <= 0b0111 => Arm64Register.S0,
                    >= 0b1000 => Arm64Register.D0,
                };
                result = result with
                {
                    Op0Reg = width + rd,
                    Op1Reg = width + rn,
                    Op2Imm = imm - esize
                };
                break;
            case Arm64Mnemonic.SQSHRN:
            case Arm64Mnemonic.SQRSHRN:
            case Arm64Mnemonic.SQSHRUN:
            case Arm64Mnemonic.SQRSHRUN:
            case Arm64Mnemonic.UQSHRN:
            case Arm64Mnemonic.UQRSHRN:
                width = immh switch
                {
                    0b0001 => Arm64Register.B0,
                    0b0010 or 0b0011 => Arm64Register.H0,
                    >= 0b0100 and <= 0b0111 => Arm64Register.S0,
                    0 or >= 0b1000 => throw new Arm64UndefinedInstructionException("Reserved"),
                };
                var width2 = immh switch
                {
                    0b0001 => Arm64Register.H0,
                    0b0010 or 0b0011 => Arm64Register.S0,
                    >= 0b0100 and <= 0b0111 => Arm64Register.D0,
                    0 or >= 0b1000 => throw new Arm64UndefinedInstructionException("Reserved"),
                };
                esize = 8 << (int)(immh >> 3); // HighestSetBit(immh)
                result = result with
                {
                    Op0Reg = width + rd,
                    Op1Reg = width2 + rn,
                    Op2Imm = (esize * 2) - imm
                };
                break;
            case Arm64Mnemonic.SCVTF:
            case Arm64Mnemonic.FCVTZS:
            case Arm64Mnemonic.UCVTF:
            case Arm64Mnemonic.FCVTZU:
                esize = immh.TestBit(3) ? 64 // if 1xxx then 64
                    : immh.TestBit(2) ? 32  // else if 01xx then 32
                    : 16; // else 16
                width = immh switch
                {
                    0b0000 or 0b0001 => throw new Arm64UndefinedInstructionException("Reserved"),
                    0b0010 or 0b0011 => Arm64Register.H0,
                    >= 0b0100 and <= 0b0111 => Arm64Register.S0,
                    >= 0b1000 => Arm64Register.D0,
                };
                result = result with
                {
                    Op0Reg = width + rd,
                    Op1Reg = width + rn,
                    Op2Imm = (esize * 2) - imm // fbits
                };
                break;
        }
        
        return result;
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

    //"Advanced SIMD Scalar Three Same" derived from C4-587 
    //Note this is NOT the "Advanced SIMD Three Same" - that's in Adm64NonScalarAdvancedSimd.AdvancedSimdThreeSame
    public static Arm64Instruction ThreeSame(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath, 
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
