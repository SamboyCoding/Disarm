﻿namespace Disarm.InternalDisassembly;

internal static class Arm64FloatingPoint
{
    internal static Arm64Instruction ConversionToAndFromFixedPoint(uint instruction)
    {
        //page 625
        
        var sf = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var ptype = (instruction >> 22) & 0b11;
        var rmode = (instruction >> 19) & 0b11;
        var opcode = (instruction >> 16) & 0b111;
        var scale = (instruction >> 10) & 0b11_1111;
        var rn = (int) (instruction >> 5) & 0b11111;
        var rd = (int) (instruction >> 0) & 0b11111;
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating-point conversion to/from fixed-point: S is reserved");
        
        if(ptype == 0b10)
            throw new Arm64UndefinedInstructionException("Floating-point conversion to/from fixed-point: ptype 0b10 is reserved");
        
        if(opcode >= 0b100)
            throw new Arm64UndefinedInstructionException($"Floating-point conversion to/from fixed-point: opcode 0x{opcode:X} (> 3) is reserved");
        
        if(!sf && scale < 0b10_0000)
            throw new Arm64UndefinedInstructionException("Floating-point conversion to/from fixed-point: sf = 0 and scale < 32 is reserved");
        
        //Now, roughly, ignoring the reserved bits we just checked:
        //sf is the size of the integer - 0 is 32-bit, 1 is 64-bit
        //ptype is precision type - 0 is single, 1 is double, 2 is reserved, 3 is half
        //rmode is rounding mode - 0 is round to nearest, 3 is round to zero. Otherwise are reserved
        //opcode is the operation:
        //000 - FCVT_S - Floating => fixed, signed
        //001 - FCVT_U - Floating => fixed, unsigned
        //010 - SCVTF - Fixed => floating, signed
        //011 - UCVTF - Fixed => floating, unsigned
        
        //Note fixed => floating require rmode = 0 and floating => fixed require rmode = 3
        
        var mnemonic = opcode switch
        {
            0b000 => Arm64Mnemonic.FCVTZS,
            0b001 => Arm64Mnemonic.FCVTZU,
            0b010 => Arm64Mnemonic.SCVTF,
            0b011 => Arm64Mnemonic.UCVTF,
            0b000100 => Arm64Mnemonic.FCVT,
            _ => throw new("Impossible opcode")
        };
        
        if (mnemonic is Arm64Mnemonic.FCVTZS or Arm64Mnemonic.FCVTZU && rmode != 3)
            throw new Arm64UndefinedInstructionException($"Floating-point conversion to/from fixed-point: FCVTZS/FCVTZU requires rmode = 3 (got {rmode})");
        
        if(mnemonic is Arm64Mnemonic.SCVTF or Arm64Mnemonic.UCVTF && rmode != 0)
            throw new Arm64UndefinedInstructionException($"Floating-point conversion to/from fixed-point: SCVTF/UCVTF requires rmode = 0 (got {rmode})");
        
        var floatingBaseReg = ptype switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };
        
        var intBaseReg = sf ? Arm64Register.X0 : Arm64Register.W0;
        
        var regD = mnemonic is Arm64Mnemonic.SCVTF or Arm64Mnemonic.UCVTF ? floatingBaseReg + rd : intBaseReg + rd;
        var regN = mnemonic is Arm64Mnemonic.SCVTF or Arm64Mnemonic.UCVTF ? intBaseReg + rn : floatingBaseReg + rn;
        
        var fbits = (int) (64 - scale);

        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointConversion,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Imm = fbits
        };
    }
    
    internal static Arm64Instruction ConversionToAndFromInteger(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var ptype = (instruction >> 22) & 0b11;
        var rmode = (instruction >> 19) & 0b11;
        var opcode = (instruction >> 16) & 0b111;
        var rn = (int) (instruction >> 5) & 0b11111;
        var rd = (int) (instruction >> 0) & 0b11111;

        if (rmode != 0 && opcode is 0b010 or 0b011 or 0b100 or 0b101)
            throw new Arm64UndefinedInstructionException($"Floating-point conversion to/from integer: rmode != 0 not allowed with opcode 0x{opcode:X}");
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating-point conversion to/from integer: S is reserved");
        
        if(ptype == 0b10 && ((opcode >> 2) == 0 || (opcode >> 1) == 0b10))
            throw new Arm64UndefinedInstructionException($"Floating-point conversion to/from integer: ptype 0b10 not allowed with opcode 0x{opcode:X}");
        
        //There are more than 3 pages of instructions here...
        //Summarising:
        //sf sets the size of the integer - 0 is 32-bit, 1 is 64-bit
        //s is unused - having it set is undefined
        //rmode is rounding mode. 0 is round to nearest (N), 1 is round to positive infinity (P), 2 is round to negative infinity (M), 3 is round to zero (Z).
        //ptype is the type of the floating point number. 0 is single, 1 is double, 2 is almost always reserved but means "top half of 128-bit", 3 is half
        //opcode is the actual operation:
        //000 - FCVT*S - Floating-point ConVert To [rmode], Signed, [rmode with ties to even for rmode = 0]
        //001 - FCVT*U - Floating-point ConVert To [rmode], Unsigned, [rmode with ties to even for rmode = 0]
        //010 - SCVTF - Signed, ConVert To Floating-point. Only defined for rmode 0
        //011 - UCVTF - Unsigned, ConVert To Floating-point. Only defined for rmode 0
        //100 - FCVT*S - Floating-point ConVert To [rmode], Signed, rmode with ties away. Only defined for rmode 0
        //101 - FCVT*U - Floating-point ConVert To [rmode], Unsigned, rmode with ties away. Only defined for rmode 0
        //110 - FMOV - floating point move without conversion, floating to integer, only defined for rmode = 0
        //111 - FMOV - floating point move without conversion, integer to floating, only defined for rmode = 0

        var mnemonic = opcode switch
        {
            0b000 or 0b100 => rmode switch
            {
                0b00 => Arm64Mnemonic.FCVTNS,
                0b01 => Arm64Mnemonic.FCVTPS,
                0b10 => Arm64Mnemonic.FCVTMS,
                0b11 => Arm64Mnemonic.FCVTZS,
                _ => throw new("Impossible rmode")
            },
            0b001 or 0b101 => rmode switch
            {
                0b00 => Arm64Mnemonic.FCVTNU,
                0b01 => Arm64Mnemonic.FCVTPU,
                0b10 => Arm64Mnemonic.FCVTMU,
                0b11 => Arm64Mnemonic.FCVTZU,
                _ => throw new("Impossible rmode")
            },
            0b010 => Arm64Mnemonic.SCVTF,
            0b011 => Arm64Mnemonic.UCVTF,
            0b110 or 0b111 => Arm64Mnemonic.FMOV,
            _ => throw new("Impossible opcode")
        };

        //FCVT* or the FMOV kind where the int is the destination
        var intRegFirst = opcode is 0b000 or 0b100 or 0b001 or 0b101 or 0b110;

        var floatingBaseReg = ptype switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b10 => Arm64Register.V0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };

        if (floatingBaseReg == Arm64Register.V0)
        {
            if(rmode != 0b01 || opcode is not 0b110 or 0b111)
                throw new("Floating-point conversion to/from integer: ptype 0b10 only allowed with rmode 0b01 and opcode 0b110 or 0b111");
        }

        var integerBaseReg = sf ? Arm64Register.X0 : Arm64Register.W0;
        
        var regD = (intRegFirst ? integerBaseReg : floatingBaseReg) + rd;
        var regN = (intRegFirst ? floatingBaseReg : integerBaseReg) + rn;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = regD,
            Op1Reg = regN,
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointConversion,
        };
    }

    public static Arm64Instruction DataProcessingOneSource(uint instruction)
    {
        var mFlag = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var ptype = (instruction >> 22) & 0b11;
        var opcode = (instruction >> 15) & 0b11_1111;
        var rn = (int) (instruction >> 5) & 0b11111;
        var rd = (int) (instruction >> 0) & 0b11111;
        
        if (mFlag)
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): M is reserved");
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): S is reserved");
        
        if(opcode.TestBit(5))
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): top bit of opcode is reserved");
        
        if(ptype == 0b11 && opcode > 0b1111)
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): ptype 0b11 only allowed with opcode 0b0000 to 0b1111");
        
        if(ptype == 0b10)
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): ptype 0b10 is reserved");

        var mnemonic = opcode switch
        {
            0b000000 => Arm64Mnemonic.FMOV,
            0b000001 => Arm64Mnemonic.FABS,
            0b000010 => Arm64Mnemonic.FNEG,
            0b000011 => Arm64Mnemonic.FSQRT,
            0b000100 => Arm64Mnemonic.FCVT,
            0b000101 => Arm64Mnemonic.FCVT,
            0b000110 => throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): opcode 0b000110 is reserved"),
            0b000111 => Arm64Mnemonic.FCVT,
            0b001000 => Arm64Mnemonic.FRINTN,
            0b001001 => Arm64Mnemonic.FRINTP,
            0b001010 => Arm64Mnemonic.FRINTM,
            0b001011 => Arm64Mnemonic.FRINTZ,
            0b001100 => Arm64Mnemonic.FRINTA,
            0b001101 => throw new Arm64UndefinedInstructionException("Floating-point data-processing (1 source): opcode 0b001101 is reserved"),
            0b001110 => Arm64Mnemonic.FRINTX,
            0b001111 => Arm64Mnemonic.FRINTI,
            0b010000 => Arm64Mnemonic.FRINT32Z,
            0b010001 => Arm64Mnemonic.FRINT32X,
            0b010010 => Arm64Mnemonic.FRINT64Z,
            0b010011 => Arm64Mnemonic.FRINT64X,
            _ => throw new Arm64UndefinedInstructionException($"Floating-point data-processing (1 source): opcode 0x{opcode:X2} is reserved")
        };

        var category = mnemonic switch
        {
            Arm64Mnemonic.FABS or Arm64Mnemonic.FNEG or Arm64Mnemonic.FSQRT => Arm64MnemonicCategory.FloatingPointMath,
            _ => Arm64MnemonicCategory.FloatingPointDataProcessing,
        };
        
        var baseReg = ptype switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };
        
        var regD = baseReg + rd;
        var regN = baseReg + rn;
//  Fix FCVT 
        if (mnemonic == Arm64Mnemonic.FCVT)
        {
            if (opcode == 0b000100) // FCVT additional variant
            {
                regD = ptype switch
                {
                    0b00 => Arm64Register.H0 + rd, // S => H
                    0b01 => Arm64Register.S0 + rd, // D => S  
                    0b11 => Arm64Register.S0 + rd, // H => S
                    _ => throw new("Impossible ptype")
                };
            }
            else if (opcode == 0b000101) // FCVT D/S
            {
                
                regD = ptype switch
                {
                    0b00 => Arm64Register.D0 + rd, // S => D
                    0b01 => Arm64Register.S0 + rd, // D => S
                    0b11 => Arm64Register.S0 + rd, // H => S
                    _ => throw new("Impossible ptype")
                };
            }
            else if (opcode == 0b000111) // FCVT H/D
            {
               
                regD = ptype switch
                {
                    0b00 => Arm64Register.H0 + rd, // S => H
                    0b01 => Arm64Register.H0 + rd, // D => H
                    0b11 => Arm64Register.D0 + rd, // H => D
                    _ => throw new("Impossible ptype")
                };
            }
        }
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

    public static Arm64Instruction DataProcessingTwoSource(uint instruction)
    {
        var mFlag = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var pType = (instruction >> 22) & 0b11;
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var opcode = (instruction >> 12) & 0b1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) (instruction >> 0) & 0b1_1111;
        
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Data processing 2-source: S flag is reserved");
        
        if(mFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Data processing 2-source: M flag is reserved");
        
        if(opcode.TestPattern(0b1001) || opcode.TestPattern(0b1010) || opcode.TestPattern(0b1100))
            throw new Arm64UndefinedInstructionException($"Floating point: Data processing 2-source: Reserved opcode used: 0x{opcode:X}");
        
        if(pType == 0b10)
            throw new Arm64UndefinedInstructionException("Floating point: Data processing 2-source: ptype 0b10 is reserved");

        var mnemonic = opcode switch
        {
            0b0000 => Arm64Mnemonic.FMUL,
            0b0001 => Arm64Mnemonic.FDIV,
            0b0010 => Arm64Mnemonic.FADD,
            0b0011 => Arm64Mnemonic.FSUB,
            0b0100 => Arm64Mnemonic.FMAX,
            0b0101 => Arm64Mnemonic.FMIN,
            0b0110 => Arm64Mnemonic.FMAXNM,
            0b0111 => Arm64Mnemonic.FMINNM,
            0b1000 => Arm64Mnemonic.FNMUL,
            _ => throw new("Impossible opcode")
        };
        
        //ptype:
        //0 - single
        //1 - double
        //2 - reserved
        //3 - half
        
        var floatingBaseReg = pType switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };
        
        var regD = floatingBaseReg + rd;
        var regN = floatingBaseReg + rn;
        var regM = floatingBaseReg + rm;
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointMath,
        };
    }

    public static Arm64Instruction DataProcessingThreeSource(uint instruction)
    {
        if (instruction.TestBit(31))
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (3 source): M is reserved");
        
        var pType = (instruction >> 22) & 0b11; // Bits 22-23
        var rm =  (int)(instruction >> 16) & 0b11111; // Bits 16-20
        var ra =  (int)(instruction >> 10) & 0b11111; // Bits 10-14
        var rn =  (int)(instruction >> 5) & 0b11111; // Bits 5-9
        var rd =  (int)instruction & 0b11111; // Bits 0-4

        var (Rm, Ra, Rn, Rd) = pType switch
        {
            0b00 => (Arm64Register.S0 + rm, Arm64Register.S0 + ra, Arm64Register.S0 + rn, Arm64Register.S0 + rd),
            0b01 => (Arm64Register.D0 + rm, Arm64Register.D0 + ra, Arm64Register.D0 + rn, Arm64Register.D0 + rd),
            0b11 => (Arm64Register.H0 + rm, Arm64Register.H0 + ra, Arm64Register.H0 + rn, Arm64Register.H0 + rd),
            _ => throw new Arm64UndefinedInstructionException("Impossible pType")
        };
        
        var o1 = (instruction >> 21) & 1;
        var o2 = (instruction >> 15) & 1;

        return new()
        {
            Mnemonic = (o1, o2) switch
            {
                (0, 0) => Arm64Mnemonic.FMADD,
                (0, 1) => Arm64Mnemonic.FMSUB,
                (1, 0) => Arm64Mnemonic.FNMADD,
                (1, 1) => Arm64Mnemonic.FNMSUB,
                _ => throw new Arm64UndefinedInstructionException("Impossible opcode")
            },
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointMath,
            // <Sd>, <Sn>, <Sm>, <Sa>
            // <Dd>, <Dn>, <Dm>, <Da>
            // <Hd>, <Hn>, <Hm>, <Ha>
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = Arm64OperandKind.Register,
            Op0Reg = Rd,
            Op1Reg = Rn,
            Op2Reg = Rm,
            Op3Reg = Ra
        };
    }

    public static Arm64Instruction Compare(uint instruction)
    {
        var mFlag = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var pType = (instruction >> 22) & 0b11;
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var op = (instruction >> 14) & 0b11;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var opcode2 = instruction & 0b1_1111;
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Compare: S flag is reserved");
        
        if(mFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Compare: M flag is reserved");
        
        if(pType == 0b10)
            throw new Arm64UndefinedInstructionException("Floating point: Compare: ptype 0b10 is reserved");
        
        if(op != 0)
            throw new Arm64UndefinedInstructionException("Floating point: Compare: values other than 0 for op are reserved");
        
        if(opcode2.TestPattern(0b1) || opcode2.TestPattern(0b10) || opcode2.TestPattern(0b100))
            throw new Arm64UndefinedInstructionException($"Floating point: Compare: Reserved opcode2: 0x{opcode2:X}");

        var mnemonic = opcode2 switch
        {
            0b00000 => Arm64Mnemonic.FCMP,
            0b01000 => Arm64Mnemonic.FCMP,
            0b10000 => Arm64Mnemonic.FCMPE,
            0b11000 => Arm64Mnemonic.FCMPE,
            _ => throw new("Impossible opcode2")
        };
        
        var baseReg = pType switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };
        
        var regN = baseReg + rn;
        var regM = baseReg + rm;

        if (opcode2.TestBit(3))
            //Zero variant
            return new()
            {
                Mnemonic = mnemonic,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Immediate,
                Op0Reg = regN,
                Op1Imm = 0,
            };
        
        //Reg variant
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = regN,
            Op1Reg = regM,
        };
    }

    public static Arm64Instruction Immediate(uint instruction)
    {
        var mFlag = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var pType = (instruction >> 22) & 0b11;
        var imm8 = (instruction >> 13) & 0b1111_1111;
        var imm5 = (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(imm5 != 0)
            throw new Arm64UndefinedInstructionException("Floating point: Immediate: all bits of imm5 are reserved");
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Immediate: S flag is reserved");
        
        if(mFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Immediate: M flag is reserved");
        
        if(pType == 0b10)
            throw new Arm64UndefinedInstructionException("Floating point: Immediate: ptype 0b10 is reserved");
        
        //Always FMOV, ptype just tells you width

        var baseReg = pType switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };
        
        var immediate = Arm64CommonUtils.DecodeFPImm(pType, imm8);

        return new()
        {
            Mnemonic = Arm64Mnemonic.FMOV,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.FloatingPointImmediate,
            Op0Reg = baseReg + rd,
            Op1FpImm = immediate,
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointDataProcessing,
        };
    }

    public static Arm64Instruction ConditionalCompare(uint instruction)
    {
        if (instruction.TestBit(31))
            throw new Arm64UndefinedInstructionException("Floating-point data-processing (3 source): M is reserved");
        
        var pType = (instruction >> 22) & 0b11; // Bits 22-23
        var rm =  (int)(instruction >> 16) & 0b11111; // Bits 16-20
        var rn =  (int)(instruction >> 5) & 0b11111; // Bits 5-9

        var (Rm, Rn) = pType switch
        {
            0b00 => (Arm64Register.S0 + rm, Arm64Register.S0 + rn),
            0b01 => (Arm64Register.D0 + rm, Arm64Register.D0 + rn),
            0b11 => (Arm64Register.H0 + rm, Arm64Register.H0 + rn),
            _ => throw new Arm64UndefinedInstructionException("Impossible pType")
        };
        
        var op = (instruction >> 4) & 1; // Bit 4
        var nzcv = instruction & 0b1111;
        var cond = (instruction >> 12) & 0b1111; // Bits 12-15
        var condition = (Arm64ConditionCode)cond;

        return new()
        {
            Mnemonic = op switch
            {
                0 => Arm64Mnemonic.FCCMP,
                1 => Arm64Mnemonic.FCCMPE,
                _ => throw new Arm64UndefinedInstructionException("Impossible opcode")
            },
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointComparison,
            // <Hn>, <Hm>, #<nzcv>, <cond>
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
            Op0Reg = Rn,
            Op1Reg = Rm,
            Op2Imm = nzcv,
            FinalOpConditionCode = condition,
        };
    }

    public static Arm64Instruction ConditionalSelect(uint instruction)
    {
        var mFlag = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var pType = (instruction >> 22) & 0b11;
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var cond = (instruction >> 12) & 0b1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Conditional select: S flag is reserved");
        
        if(mFlag)
            throw new Arm64UndefinedInstructionException("Floating point: Conditional select: M flag is reserved");
        
        if(pType == 0b10)
            throw new Arm64UndefinedInstructionException("Floating point: Conditional select: ptype 0b10 is reserved");
        
        var baseReg = pType switch
        {
            0b00 => Arm64Register.S0,
            0b01 => Arm64Register.D0,
            0b11 => Arm64Register.H0,
            _ => throw new("Impossible ptype"),
        };
        
        var regD = baseReg + rd;
        var regN = baseReg + rn;
        var regM = baseReg + rm;

        var condition = (Arm64ConditionCode)cond;

        return new()
        {
            Mnemonic = Arm64Mnemonic.FCSEL,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            FinalOpConditionCode = condition,
            MnemonicCategory = Arm64MnemonicCategory.FloatingPointComparison,
        };
    }
}
