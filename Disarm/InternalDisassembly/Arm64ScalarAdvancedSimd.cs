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
                esize = 8 << Arm64CommonUtils.HighestSetBit(immh, 4);
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
                esize = 8 << Arm64CommonUtils.HighestSetBit(immh, 4);
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
        var u = instruction.TestBit(29); // Bit 29
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var l = instruction.TestBit(21) ? 1 : 0 ; // Bit 21
        var m = instruction.TestBit(20) ? 1 : 0; // Bit 20
        var rm = (int) (instruction >> 16) & 0b1111; //Bits 16-19
        var opcode = (instruction >> 12) & 0b1111; // Bits 12-15
        var h = instruction.TestBit(11) ? 1 : 0; // Bit 11
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4
        
        // required for FM** instructions
        var szl = (instruction >> 21) & 0b11; // Bits 21-22
        var sz = instruction.TestBit(22); // Bit 22
        
        var result = new Arm64Instruction()
        {
            Mnemonic = u switch
            {
                false => opcode switch
                {
                    0b0011 => Arm64Mnemonic.SQDMLAL,
                    0b0111 => Arm64Mnemonic.SQDMLSL,
                    0b1011 => Arm64Mnemonic.SQDMULL,
                    0b1100 => Arm64Mnemonic.SQDMULH,
                    0b1101 => Arm64Mnemonic.SQRDMULH,
                    // 00 for FP16 and 1X for Single/Double
                    0b0001 when size != 0b01 => Arm64Mnemonic.FMLA,
                    0b0101 when size != 0b01 => Arm64Mnemonic.FMLS,
                    0b1001 when size != 0b01 => Arm64Mnemonic.FMUL,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                },
                true => opcode switch
                {
                    0b1101 => Arm64Mnemonic.SQRDMLAH,
                    0b1111 => Arm64Mnemonic.SQRDMLSH,
                    // 00 for FP16 and 1X for Single/Double
                    0b1001 when size != 0b01 => Arm64Mnemonic.FMULX,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                }
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.VectorRegisterElement,
        };

        switch (result.Mnemonic)
        {
            // <Va><d>, <Vb><n>, <Vm>.<Ts>[<index>]
            case Arm64Mnemonic.SQDMLAL:
            case Arm64Mnemonic.SQDMLSL:
            case Arm64Mnemonic.SQDMULL:
                result = result with
                {
                    Op0Reg = size switch
                    {
                        0b01 => Arm64Register.S0,
                        0b10 => Arm64Register.D0,
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    } + rd,
                    Op1Reg = size switch
                    {
                        0b01 => Arm64Register.H0,
                        0b10 => Arm64Register.S0,
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    } + rn,
                    Op2Reg = size switch
                    {
                        0b01 => Arm64Register.V0 + rm,
                        0b10 => Arm64Register.V0 + (rm | (m << 5)),
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    },
                    Op2VectorElement = size switch
                    {
                        0b01 => new(Arm64VectorElementWidth.H, (h << 2) | (l << 1) | m),
                        0b10 => new(Arm64VectorElementWidth.S, (h << 1) | l),
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    }
                };
                break;
            // <V><d>, <V><n>, <Vm>.<Ts>[<index>]
            case Arm64Mnemonic.SQDMULH:
            case Arm64Mnemonic.SQRDMULH:
            case Arm64Mnemonic.SQRDMLAH:
            case Arm64Mnemonic.SQRDMLSH:
                result = result with
                {
                    Op0Reg = size switch
                    {
                        0b01 => Arm64Register.H0,
                        0b10 => Arm64Register.S0,
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    } + rd,
                    Op1Reg = size switch
                    {
                        0b01 => Arm64Register.H0,
                        0b10 => Arm64Register.S0,
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    } + rn,
                    Op2Reg = size switch
                    {
                        0b01 => Arm64Register.V0 + rm,
                        0b10 => Arm64Register.V0 + (rm | (m << 5)),
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    },
                    Op2VectorElement = size switch
                    {
                        0b01 => new(Arm64VectorElementWidth.H, (h << 2) | (l << 1) | m),
                        0b10 => new(Arm64VectorElementWidth.S, (h << 1) | l),
                        _ => throw new Arm64UndefinedInstructionException("Reserved")
                    }
                };
                break;
            //  <Hd>, <Hn>, <Vm>.H[<index>] for FEAT_FP16 && size == 0
            //  <V><d>, <V><n>, <Vm>.<Ts>[<index>]
            case Arm64Mnemonic.FMLA:
            case Arm64Mnemonic.FMLS:
            case Arm64Mnemonic.FMUL:
            case Arm64Mnemonic.FMULX:
                var reg = size switch
                {
                    0 => Arm64Register.H0,
                    0b10 or 0b11 => sz switch
                    {
                        false => Arm64Register.S0,
                        true => Arm64Register.D0,
                    },
                    _ => throw new Arm64UndefinedInstructionException("Unexpected")
                };
                result = result with
                {
                    Op0Reg = reg + rd,
                    Op1Reg = reg + rn,
                    Op2Reg = Arm64Register.V0 + size switch
                    {
                        0 => rm,
                        _ => rm | (m << 5)
                    },
                    Op2VectorElement = size switch
                    {
                        0 => new Arm64VectorElement(Arm64VectorElementWidth.H, (h << 2) | (l << 1) | m), // H:L:M for fp16
                        _ => new Arm64VectorElement(sz ? Arm64VectorElementWidth.D : Arm64VectorElementWidth.S, 
                            (sz ? 1 : 0, l) switch
                            {
                                (0, _) => (h << 1) | l,
                                (1, 0) => h,
                                _ => throw new Arm64UndefinedInstructionException("Reserved")
                            })
                    },
                };
                break;
        }
        
        return result;
    }

    public static Arm64Instruction TwoRegisterMiscFp16(uint instruction)
    {
        var u = (instruction >> 29) & 1; // Bit 29
        var a = (instruction >> 23) & 1; // Bit 23
        var opcode = (instruction >> 12) & 0b1_1111; // Bits 12-16
        var rd = (int)(instruction >> 5) & 0b1_1111; // Bits 5-9
        var rn = (int)instruction & 0b1_1111; // Bits 0-4
        
        return new ()
        {
            Mnemonic = (u, a, opcode) switch
            {
                (0, 0, 0b11010) => Arm64Mnemonic.FCVTNS,
                (0, 0, 0b11011) => Arm64Mnemonic.FCVTMS,
                (0, 0, 0b11100) => Arm64Mnemonic.FCVTAS,
                (0, 0, 0b11101) => Arm64Mnemonic.SCVTF,
                
                (0, 1, 0b01100) => Arm64Mnemonic.FCMGT,
                (0, 1, 0b01101) => Arm64Mnemonic.FCMEQ,
                (0, 1, 0b01110) => Arm64Mnemonic.FCMLT,
                (0, 1, 0b11010) => Arm64Mnemonic.FCVTPS,
                (0, 1, 0b11011) => Arm64Mnemonic.FCVTZS,
                (0, 1, 0b11101) => Arm64Mnemonic.FRECPE,
                (0, 1, 0b11111) => Arm64Mnemonic.FRECPX,
                
                (1, 0, 0b11010) => Arm64Mnemonic.FCVTNU,
                (1, 0, 0b11011) => Arm64Mnemonic.FCVTMU,
                (1, 0, 0b11100) => Arm64Mnemonic.FCVTAU,
                (1, 0, 0b11101) => Arm64Mnemonic.UCVTF,
                
                (1, 1, 0b01100) => Arm64Mnemonic.FCMGE,
                (1, 1, 0b01101) => Arm64Mnemonic.FCMLE,
                (1, 1, 0b11010) => Arm64Mnemonic.FCVTPU,
                (1, 1, 0b11011) => Arm64Mnemonic.FCVTZU,
                (1, 1, 0b11101) => Arm64Mnemonic.FRSQRTE,
                _ => throw new Arm64UndefinedInstructionException("Unallocated")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.H0 + rd,
            Op1Reg = Arm64Register.H0 + rn,
        };
    }

    public static Arm64Instruction TwoRegisterMisc(uint instruction)
    {
        var uFlag = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11; //Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; //Bits 12-16
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4

        var sz = instruction.TestBit(22);
        
        var result = new Arm64Instruction()
        {
            Mnemonic = uFlag switch
            {
                false => opcode switch
                {
                    0b00011 => Arm64Mnemonic.SUQADD,
                    0b00111 => Arm64Mnemonic.SQABS,
                    0b01000 => Arm64Mnemonic.CMGT,
                    0b01001 => Arm64Mnemonic.CMEQ,
                    0b01010 => Arm64Mnemonic.CMLT,
                    0b01011 => Arm64Mnemonic.ABS,
                    0b10100 => Arm64Mnemonic.SQXTN,
                    0b11010 when size is 0 or 1 => Arm64Mnemonic.FCVTNS,
                    0b11011 when size is 0 or 1 => Arm64Mnemonic.FCVTMS,
                    0b11100 when size is 0 or 1 => Arm64Mnemonic.FCVTAS,
                    0b11101 when size is 0 or 1 => Arm64Mnemonic.SCVTF,
                    0b01100 when size is 2 or 3 => Arm64Mnemonic.FCMGT,
                    0b01101 when size is 2 or 3 => Arm64Mnemonic.FCMEQ,
                    0b01110 when size is 2 or 3 => Arm64Mnemonic.FCMLT,
                    0b11010 when size is 2 or 3 => Arm64Mnemonic.FCVTPS,
                    0b11011 when size is 2 or 3 => Arm64Mnemonic.FCVTZS,
                    0b11101 when size is 2 or 3 => Arm64Mnemonic.FRECPE,
                    0b11111 when size is 2 or 3 => Arm64Mnemonic.FRECPX,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                },
                true => opcode switch
                {
                    0b00011 => Arm64Mnemonic.USQADD,
                    0b00111 => Arm64Mnemonic.SQNEG,
                    0b01000 => Arm64Mnemonic.CMGE,
                    0b01001 => Arm64Mnemonic.CMLE,
                    0b01011 => Arm64Mnemonic.NEG,
                    0b10010 => Arm64Mnemonic.SQXTUN,
                    0b10100 => Arm64Mnemonic.UQXTN,
                    0b10110 when size is 0 or 1 => Arm64Mnemonic.FCVTXN,
                    0b11010 when size is 0 or 1 =>  Arm64Mnemonic.FCVTNU,
                    0b11011 when size is 0 or 1 => Arm64Mnemonic.FCVTMU,
                    0b11100 when size is 0 or 1 =>  Arm64Mnemonic.FCVTAU,
                    0b11101 when size is 0 or 1 => Arm64Mnemonic.UCVTF,
                    0b01100 when size is 2 or 3 => Arm64Mnemonic.FCMGE,
                    0b01101 when size is 2 or 3 => Arm64Mnemonic.FCMLE,
                    0b11010 when size is 2 or 3 =>  Arm64Mnemonic.FCVTPU,
                    0b11011 when size is 2 or 3 =>  Arm64Mnemonic.FCVTZU,
                    0b11101 when size is 2 or 3 => Arm64Mnemonic.FRSQRTE,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                }
            },
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
        };

        Arm64Register baseRegister;
        Arm64Register baseRegister2;
        
        switch (result.Mnemonic)
        {
            case Arm64Mnemonic.SUQADD:
            case Arm64Mnemonic.SQABS:
            case Arm64Mnemonic.USQADD:
            case Arm64Mnemonic.SQNEG:
                baseRegister = size switch
                {
                    0 => Arm64Register.B0,
                    1 => Arm64Register.H0,
                    2 => Arm64Register.S0,
                    3 => Arm64Register.D0,
                    _ => throw new IndexOutOfRangeException()
                };
                result = result with
                {
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister + rn
                };
                break;
            case Arm64Mnemonic.CMGT:
            case Arm64Mnemonic.CMGE:
            case Arm64Mnemonic.CMEQ:
            case Arm64Mnemonic.CMLT:
            case Arm64Mnemonic.CMLE:
                baseRegister = size switch
                {
                    0 => Arm64Register.B0,
                    1 => Arm64Register.H0,
                    2 => Arm64Register.S0,
                    3 => Arm64Register.D0,
                    _ => throw new IndexOutOfRangeException()
                };
                result = result with
                {
                    Op3Kind = Arm64OperandKind.Immediate,
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister + rn,
                    Op2Imm = 0
                };
                break;
            case Arm64Mnemonic.ABS:
            case Arm64Mnemonic.NEG:
                baseRegister = size switch
                {
                    0b11 => Arm64Register.D0,
                    _ => throw new Arm64UndefinedInstructionException("Reserved")
                };
                result = result with
                {
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister + rn
                };
                break;
            case Arm64Mnemonic.SQXTN:
            case Arm64Mnemonic.SQXTUN:
            case Arm64Mnemonic.UQXTN:
                
                baseRegister = size switch
                {
                    0 => Arm64Register.B0,
                    1 => Arm64Register.H0,
                    2 => Arm64Register.S0,
                    _ => throw new Arm64UndefinedInstructionException("Reserved")
                };
                baseRegister2 = size switch
                {
                    0 => Arm64Register.H0,
                    1 => Arm64Register.S0,
                    2 => Arm64Register.D0,
                    _ => throw new Arm64UndefinedInstructionException("Reserved")
                };
                result = result with
                {
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister2 + rn
                };
                break;
            case Arm64Mnemonic.FCVTNS:
            case Arm64Mnemonic.FCVTMS:
            case Arm64Mnemonic.FCVTAS:
            case Arm64Mnemonic.SCVTF:
            case Arm64Mnemonic.FCVTPS:
            case Arm64Mnemonic.FCVTZS:
            case Arm64Mnemonic.FRECPE:
            case Arm64Mnemonic.FRECPX:
            case Arm64Mnemonic.FCVTNU:
            case Arm64Mnemonic.FCVTMU:
            case Arm64Mnemonic.FCVTAU:
            case Arm64Mnemonic.UCVTF:
            case Arm64Mnemonic.FCVTPU:
            case Arm64Mnemonic.FCVTZU:
            case Arm64Mnemonic.FRSQRTE:
                baseRegister = sz switch
                {
                    false => Arm64Register.S0,
                    true => Arm64Register.D0
                };
                result = result with
                {
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister + rn
                };
                break;
            case Arm64Mnemonic.FCVTXN:
                baseRegister = sz switch
                {
                    false => throw new Arm64UndefinedInstructionException("Reserved"),
                    true => Arm64Register.S0
                };
                baseRegister2 = sz switch
                {
                    false => throw new Arm64UndefinedInstructionException("Reserved"),
                    true => Arm64Register.D0
                };
                result = result with
                {
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister2 + rn
                };
                break;
            case Arm64Mnemonic.FCMGT:
            case Arm64Mnemonic.FCMGE:
            case Arm64Mnemonic.FCMEQ:
            case Arm64Mnemonic.FCMLT:
            case Arm64Mnemonic.FCMLE:
                baseRegister = sz switch
                {
                    false => Arm64Register.S0,
                    true => Arm64Register.D0
                };
                result = result with
                {
                    Op2Kind = Arm64OperandKind.FloatingPointImmediate,
                    Op0Reg = baseRegister + rd,
                    Op1Reg = baseRegister + rn,
                    Op2FpImm = 0f
                };
                break;
        }
        
        return result;
    }
    
    public static Arm64Instruction Pairwise(uint instruction)
    {
        var uFlag = instruction.TestBit(29);
        var size = (instruction >> 22) & 0b11; //Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; //Bits 12-16
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4

        var sz = instruction.TestBit(22);
        
        var result = new Arm64Instruction()
        {
            Mnemonic = opcode switch
            {
                // uFlag for H or S/D
                0b11011 when !uFlag => Arm64Mnemonic.ADDP,
                0b01100 when size is 0 or 1 => Arm64Mnemonic.FMAXNMP,
                0b01101 when size is 0 or 1 => Arm64Mnemonic.FADDP,
                0b01111 when size is 0 or 1 => Arm64Mnemonic.FMAXP,
                0b01100 when size is 2 or 3 => Arm64Mnemonic.FMINNMP,
                0b01111 when size is 2 or 3 => Arm64Mnemonic.FMINP,
                _ => throw new Arm64UndefinedInstructionException("Unallocated"),
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op1Reg = Arm64Register.V0 + rn,
        };

        switch (result.Mnemonic)
        {
            case Arm64Mnemonic.ADDP: // only for addp
                result = result with
                {
                    Op0Reg = size switch
                    {
                        0b11 => Arm64Register.D0 + rd,
                        _ => throw new Arm64UndefinedInstructionException("Reserved"),
                    },
                    Op1Arrangement = size switch
                    {
                        0b11 => Arm64ArrangementSpecifier.TwoD,
                        _ => throw new Arm64UndefinedInstructionException("Reserved"),
                    }
                };
                break;
            default: // any other
                result = result with
                {
                    Op0Reg = sz switch
                    {
                        false when !uFlag => Arm64Register.H0,
                        false => Arm64Register.S0,
                        true when uFlag => Arm64Register.D0,
                        _ => throw new Arm64UndefinedInstructionException("Reserved"),
                    } + rd,
                    Op1Arrangement = sz switch
                    {
                        false when !uFlag => Arm64ArrangementSpecifier.TwoH,
                        false => Arm64ArrangementSpecifier.TwoS,
                        true when uFlag => Arm64ArrangementSpecifier.TwoD,
                        _ => throw new Arm64UndefinedInstructionException("Reserved"),
                    }
                };
                break;
        }
        
        return result;
    }

    public static Arm64Instruction ThreeDifferent(uint instruction)
    {
        var uFlag = instruction.TestBit(29);

        if (uFlag)
            throw new Arm64UndefinedInstructionException("Unallocated");
        
        var size = (instruction >> 22) & 0b11; //Bits 22-23
        var rm = (int) (instruction >> 5) & 0b1_1111; //Bits 16-20
        var opcode = (instruction >> 12) & 0b1111; //Bits 12-15
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4
        
        return new()
        {
            Mnemonic = opcode switch
            {
                0b1001 => Arm64Mnemonic.SQDMLAL,
                0b1011 => Arm64Mnemonic.SQDMLSL,
                0b1101 => Arm64Mnemonic.SQDMULL,
                _ => throw new Arm64UndefinedInstructionException("Unallocated")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath, 
            // <Va><d>, <Vb><n>, <Vb><m>
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = size switch
            {
                0b01 => Arm64Register.S0,
                0b10 => Arm64Register.D0,
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            } + rd,
            Op1Reg = size switch
            {
                0b01 => Arm64Register.H0,
                0b10 => Arm64Register.S0,
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            } + rn,
            Op2Reg = size switch
            {
                0b01 => Arm64Register.H0,
                0b10 => Arm64Register.S0,
                _ => throw new Arm64UndefinedInstructionException("Reserved")
            } + rm,
        };
    }

    //"Advanced SIMD Scalar Three Same" derived from C4-587 
    //Note this is NOT the "Advanced SIMD Three Same" - that's in Adm64NonScalarAdvancedSimd.AdvancedSimdThreeSame
    public static Arm64Instruction ThreeSame(uint instruction)
    {
        var uFlag = instruction.TestBit(29); // Bit 29
        var size = (instruction >> 22) & 0b11; //Bits 22-23
        var rm = (int) (instruction >> 5) & 0b1_1111; //Bits 16-20
        var opcode = (instruction >> 11) & 0b1_1111; //Bits 11-15
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4
        
        var sz = instruction.TestBit(22); // Bit 22
        
        var result = new Arm64Instruction()
        {
            Mnemonic = uFlag switch
            {
                false => opcode switch
                {
                    0b00001 => Arm64Mnemonic.SQADD,
                    0b00101 => Arm64Mnemonic.SQSUB,
                    0b00110 => Arm64Mnemonic.CMGT,
                    0b00111 => Arm64Mnemonic.CMGE,
                    0b01000 => Arm64Mnemonic.SSHL,
                    0b01001 => Arm64Mnemonic.SQSHL,
                    0b01010 => Arm64Mnemonic.SRSHL,
                    0b01011 => Arm64Mnemonic.SQRSHL,
                    0b10000 => Arm64Mnemonic.ADD,
                    0b10001 => Arm64Mnemonic.CMTST,
                    0b10110 => Arm64Mnemonic.SQDMULH,
                    0b11011 when size is 0 or 1 => Arm64Mnemonic.FMULX,
                    0b11100 when size is 0 or 1 => Arm64Mnemonic.FCMEQ,
                    0b11111 when size is 0 or 1 => Arm64Mnemonic.FRECPS,
                    0b11111 when size is 2 or 3 => Arm64Mnemonic.FRSQRTS,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                },
                true => opcode switch
                {
                    0b00001 => Arm64Mnemonic.UQADD,
                    0b00101 => Arm64Mnemonic.UQSUB,
                    0b00110 => Arm64Mnemonic.CMHI,
                    0b00111 => Arm64Mnemonic.CMHS,
                    0b01000 => Arm64Mnemonic.USHL,
                    0b01001 => Arm64Mnemonic.UQSHL,
                    0b01010 => Arm64Mnemonic.URSHL,
                    0b01011 => Arm64Mnemonic.UQRSHL,
                    0b10000 => Arm64Mnemonic.SUB,
                    0b10001 => Arm64Mnemonic.CMEQ,
                    0b10110 => Arm64Mnemonic.SQRDMULH,
                    0b11100 when size is 0 or 1 => Arm64Mnemonic.FCMGE,
                    0b11101 when size is 0 or 1 => Arm64Mnemonic.FACGE,
                    0b11010 when size is 2 or 3 => Arm64Mnemonic.FABD,
                    0b11100 when size is 2 or 3 => Arm64Mnemonic.FCMGT,
                    0b11101 when size is 2 or 3 => Arm64Mnemonic.FACGT,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                }
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
        };

        Arm64Register baseRegister;
        
        switch (result.Mnemonic)
        {
            case Arm64Mnemonic.SQADD:
            case Arm64Mnemonic.SQSUB:
            case Arm64Mnemonic.SQSHL:
            case Arm64Mnemonic.SQRSHL:
            case Arm64Mnemonic.UQADD:
            case Arm64Mnemonic.UQSUB:
            case Arm64Mnemonic.UQSHL:
            case Arm64Mnemonic.UQRSHL:
                baseRegister = size switch
                {
                    0 => Arm64Register.B0,
                    1 => Arm64Register.H0,
                    2 => Arm64Register.S0,
                    3 => Arm64Register.D0,
                    _ => throw new IndexOutOfRangeException()
                };
                break;
            
            case Arm64Mnemonic.CMGT:
            case Arm64Mnemonic.CMGE:
            case Arm64Mnemonic.SSHL:
            case Arm64Mnemonic.SRSHL:
            case Arm64Mnemonic.ADD:
            case Arm64Mnemonic.CMTST:
            case Arm64Mnemonic.CMHI:
            case Arm64Mnemonic.CMHS:
            case Arm64Mnemonic.USHL:
            case Arm64Mnemonic.URSHL:
            case Arm64Mnemonic.SUB:
            case Arm64Mnemonic.CMEQ:
                baseRegister = size switch
                {
                    0b11 => Arm64Register.D0,
                    _ => throw new Arm64UndefinedInstructionException("Reserved")
                };
                break;
            
            case Arm64Mnemonic.SQDMULH:
            case Arm64Mnemonic.SQRDMULH:
                baseRegister = size switch
                {
                    0b01 => Arm64Register.H0,
                    0b10 => Arm64Register.S0,
                    _ => throw new Arm64UndefinedInstructionException("Reserved")
                };
                break;
            
            case Arm64Mnemonic.FMULX:
            case Arm64Mnemonic.FCMEQ:
            case Arm64Mnemonic.FRECPS:
            case Arm64Mnemonic.FRSQRTS:
            case Arm64Mnemonic.FCMGE:
            case Arm64Mnemonic.FACGE:
            case Arm64Mnemonic.FABD:
            case Arm64Mnemonic.FCMGT:
            case Arm64Mnemonic.FACGT:
                baseRegister = sz switch
                {
                    false => Arm64Register.S0,
                    true => Arm64Register.D0,
                };
                break;
            
            default:
                baseRegister = Arm64Register.INVALID;
                break;
        }

        return result with
        {
            Op0Reg = baseRegister + rd,
            Op1Reg = baseRegister + rn,
            Op2Reg = baseRegister + rm,
        };
    }

    public static Arm64Instruction ThreeSameFp16(uint instruction)
    {
        var uFlag = instruction.TestBit(29); // Bit 29
        var rm = (int) (instruction >> 5) & 0b1_1111; //Bits 16-20
        var opcode = (instruction >> 11) & 0b111; //Bits 11-13
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4
        
        var aFlag = instruction.TestBit(23); // Bit 23
        
        return new()
        {
            Mnemonic = uFlag switch
            {
                false => opcode switch
                {
                    0b011 when !aFlag => Arm64Mnemonic.FMULX,
                    0b100 when !aFlag => Arm64Mnemonic.FCMEQ,
                    0b111 when !aFlag => Arm64Mnemonic.FRECPS,
                    0b111 when aFlag => Arm64Mnemonic.FRSQRTS,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                },
                true => opcode switch
                {
                    0b100 when !aFlag => Arm64Mnemonic.FCMGE,
                    0b101 when !aFlag => Arm64Mnemonic.FACGE,
                    0b010 when aFlag => Arm64Mnemonic.FABD,
                    0b100 when aFlag => Arm64Mnemonic.FCMGT,
                    0b101 when aFlag => Arm64Mnemonic.FACGT,
                    _ => throw new Arm64UndefinedInstructionException("Unallocated")
                }
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.H0 + rd,
            Op1Reg = Arm64Register.H0 + rn,
            Op2Reg = Arm64Register.H0 + rm,
        };
    }

    public static Arm64Instruction ThreeSameExtra(uint instruction)
    {
        var uFlag = instruction.TestBit(29); // Bit 29

        if (!uFlag)
            throw new Arm64UndefinedInstructionException("Unallocated");
        
        var size = (instruction >> 22) & 0b11; //Bits 22-23
        var rm = (int) (instruction >> 5) & 0b1_1111; //Bits 16-20
        var opcode = (instruction >> 11) & 0b1111; //Bits 11-14
        var rn = (int) (instruction >> 5) & 0b1_1111; //Bits 5-9
        var rd = (int) instruction & 0b1_1111; //Bits 0-4

        Arm64Register baseRegister = size switch
        {
            0b10 => Arm64Register.H0,
            0b11 => Arm64Register.S0,
            _ => throw new Arm64UndefinedInstructionException("Reserved")
        };
        
        return new()
        {
            Mnemonic = opcode switch
            {
                0b0000 => Arm64Mnemonic.SQRDMLAH,
                0b0001 => Arm64Mnemonic.SQRDMLSH,
                _ => throw new Arm64UndefinedInstructionException("Unallocated")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdScalarMath,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = baseRegister + rd,
            Op1Reg = baseRegister + rn,
            Op2Reg = baseRegister + rm,
        };
    }
}
