namespace Disarm.InternalDisassembly;

internal static class Arm64DataProcessingRegister
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op0 = instruction.TestBit(30); //Bit 30
        var op1 = instruction.TestBit(28); //Bit 28
        //25-27 must be 101
        var op2 = (instruction >> 21) & 0b1111; //Bits 21-24
        var op3 = (instruction >> 10) & 0b11_1111; //Bits 10-15

        if (op2 == 0b0110 && op1)
            return op0
                ? DataProcessing1Source(instruction)
                : DataProcessing2Source(instruction);

        if (!op1)
        {
            if (op2 >> 3 == 0)
                return LogicalShiftedRegister(instruction);
            
            if((op2 & 0b1001) == 0b1000)
                return AddSubtractShiftedRegister(instruction);
            
            return AddSubtractExtendedRegister(instruction);
        }

        return op2 switch
        {
            0b0000 when op3 == 0 => AddSubtractWithCarry(instruction),
            0b0000 when op3 is 0b100001 or 0b000001 => RotateRightIntoFlags(instruction),
            0b0000 when (op3 & 0b1111) == 0b0010 => EvaluateIntoFlags(instruction),
            0b0010 when op3.TestBit(1) => ConditionalCompare(instruction, false),
            0b0010 => ConditionalCompare(instruction, true),
            0b0100 => ConditionalSelect(instruction),
            _ => DataProcessing3Source(instruction)
        };
    }

    private static Arm64Instruction DataProcessing1Source(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var opcode = (instruction >> 10) & 0b11_1111;
        var opcode2 = (instruction >> 16) & 0b1_1111;
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rd = (int)instruction & 0b1_1111;
        
        if(sFlag)
            throw new Arm64UndefinedInstructionException("DataProcessing1Source: S flag set");
        
        if(opcode.TestBit(6))
            throw new Arm64UndefinedInstructionException("DataProcessing1Source: top bit of opcode set");
        
        if(opcode2 > 1)
            throw new Arm64UndefinedInstructionException("DataProcessing1Source: opcode2 > 1");

        if (opcode2 == 1)
        {
            //FEAT_PAUTH stuff. Not implemented in disarm, yet.
            //But also literally not defined if sf == 0
            
            if(!sf)
                throw new Arm64UndefinedInstructionException("DataProcessing1Source: opcode2 == 1 and sf == 0");
            
            return new()
            {
                Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
                MnemonicCategory = Arm64MnemonicCategory.PointerAuthentication,
            };
        }
        
        if(opcode > 0b00_0101)
            //Anything above this is FEAT_PAUTH stuff, so not defined if that's not set.
            throw new Arm64UndefinedInstructionException($"DataProcessing1Source: opcode > 0b00_0101: {opcode:X} when opcode2 == 0");
        
        var baseReg = sf ? Arm64Register.X0 : Arm64Register.W0; //sf == 1 means 64-bit variant

        var mnemonic = opcode switch
        {
            0b00_0000 => Arm64Mnemonic.RBIT,
            0b00_0001 => Arm64Mnemonic.REV16,
            0b00_0010 when !sf => Arm64Mnemonic.REV,
            0b00_0010 => Arm64Mnemonic.REV32,
            //This would be REV64 but on a 32-bit register, which is invalid
            0b00_0011 when !sf => throw new Arm64UndefinedInstructionException("DataProcessing1Source: opcode == 0b00_0011 and sf == 0"),
            0b00_0011 => Arm64Mnemonic.REV,
            0b00_0100 => Arm64Mnemonic.CLZ,
            0b00_0101 => Arm64Mnemonic.CLS,
        };
        
        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.GeneralDataProcessing,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = baseReg + rd,
            Op1Reg = baseReg + rn,
        };
    }

    private static Arm64Instruction DataProcessing2Source(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var sFlag = instruction.TestBit(29);
        var rm = (int)(instruction >> 16) & 0b1_1111;
        var opcode = (int)(instruction >> 10) & 0b11_1111;
        var rn = (int)(instruction >> 5) & 0b1_1111;
        var rd = (int)instruction & 0b1_1111;
        
        if(opcode == 1 || (opcode >> 5) == 1 || (opcode >> 3) == 0b011)
            throw new Arm64UndefinedInstructionException($"Invalid opcode for DataProcessing2Source: {opcode:X}");
        
        if(!sf && opcode == 0)
            throw new Arm64UndefinedInstructionException($"Invalid opcode for DataProcessing2Source: {opcode:X} when sf = 0");
        
        //Just going to implement what exists and fall-through to the undefined exception

        if (!sf && !sFlag)
        {
            var mnemonic = opcode switch
            {
                0b000010 => Arm64Mnemonic.UDIV,
                0b000011 => Arm64Mnemonic.SDIV,
                0b001000 => Arm64Mnemonic.LSLV,
                0b001001 => Arm64Mnemonic.LSRV,
                0b001010 => Arm64Mnemonic.ASRV,
                0b001011 => Arm64Mnemonic.RORV,
                0b010000 => Arm64Mnemonic.CRC32B,
                0b010001 => Arm64Mnemonic.CRC32H,
                0b010010 => Arm64Mnemonic.CRC32W,
                0b010100 => Arm64Mnemonic.CRC32CB,
                0b010101 => Arm64Mnemonic.CRC32CH,
                0b010110 => Arm64Mnemonic.CRC32CW,
                _ => throw new Arm64UndefinedInstructionException($"DataProcessing2Source: opcode {opcode:X} with sf == S == 0")
            };

            return new()
            {
                Mnemonic = mnemonic,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.W0 + rd,
                Op1Reg = Arm64Register.W0 + rn,
                Op2Reg = Arm64Register.W0 + rm,
                MnemonicCategory = Arm64MnemonicCategory.Math,
            };
        }

        if (sf && sFlag)
        {
            if(opcode != 0)
                throw new Arm64UndefinedInstructionException("DataProcessing2Source: opcode != 0 when sf == S == 1");

            return new()
            {
                Mnemonic = Arm64Mnemonic.SUBPS,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rd,
                Op1Reg = Arm64Register.X0 + rn,
                Op2Reg = Arm64Register.X0 + rm,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
            };
        }
        
        //sf but no S

        var mnemonic2 = opcode switch
        {
            0b000000 => Arm64Mnemonic.SUBP,
            0b000010 => Arm64Mnemonic.UDIV,
            0b000011 => Arm64Mnemonic.SDIV,
            0b000100 => Arm64Mnemonic.IRG,
            0b000101 => Arm64Mnemonic.GMI,
            0b001000 => Arm64Mnemonic.LSLV,
            0b001001 => Arm64Mnemonic.LSRV,
            0b001010 => Arm64Mnemonic.ASRV,
            0b001011 => Arm64Mnemonic.RORV,
            0b001100 => Arm64Mnemonic.PACGA,
            0b010011 => Arm64Mnemonic.CRC32X,
            0b010111 => Arm64Mnemonic.CRC32CX,
            _ => throw new Arm64UndefinedInstructionException($"DataProcessing2Source: opcode {opcode:X} with sf == 1 and S == 0")
        };

        var category = mnemonic2 switch
        {
            Arm64Mnemonic.IRG or Arm64Mnemonic.GMI or Arm64Mnemonic.SUBP => Arm64MnemonicCategory.MemoryTagging,
            Arm64Mnemonic.PACGA => Arm64MnemonicCategory.PointerAuthentication,
            _ => Arm64MnemonicCategory.Math,
        };

        return new()
        {
            Mnemonic = mnemonic2,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.X0 + rd,
            Op1Reg = Arm64Register.X0 + rn,
            Op2Reg = Arm64Register.X0 + rm,
            MnemonicCategory = category,
        };
    }

    private static Arm64Instruction LogicalShiftedRegister(uint instruction)
    {
        var is64Bit = instruction.TestBit(31); //sf flag
        var opc = (instruction >> 29) & 0b11;
        var shift = (instruction >> 22) & 0b11;
        var negateFlag = instruction.TestBit(21); //N flag - defines if the result is negated
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var imm6 = (instruction >> 10) & 0b11_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(!is64Bit && imm6.TestBit(5))
            throw new Arm64UndefinedInstructionException("LogicalShiftedRegister: imm6 bit 5 set and sf = 0");

        var opcode = opc switch
        {
            0b00 when negateFlag => Arm64Mnemonic.BIC,
            0b00 => Arm64Mnemonic.AND,
            0b01 when negateFlag => Arm64Mnemonic.ORN,
            0b01 => Arm64Mnemonic.ORR,
            0b10 when negateFlag => Arm64Mnemonic.EON,
            0b10 => Arm64Mnemonic.EOR,
            0b11 when negateFlag => Arm64Mnemonic.BICS,
            0b11 => Arm64Mnemonic.ANDS,
            _ => throw new("LogicalShiftedRegister: impossible opc")
        };

        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var regD = baseReg + rd;
        var regN = baseReg + rn;
        var regM = baseReg + rm;


        return new()
        {
            Mnemonic = opcode,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            Op3Imm = imm6,
            MnemonicCategory = Arm64MnemonicCategory.Math
        };
    }
    
    private static Arm64Instruction AddSubtractShiftedRegister(uint instruction)
    {
        var is64Bit = instruction.TestBit(31);
        var isSubtract = instruction.TestBit(30);
        var setFlags = instruction.TestBit(29);
        var shift = (Arm64ShiftType) ((instruction >> 22) & 0b11);
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var shiftAmount = (instruction >> 10) & 0b11_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        var mnemonic = isSubtract
            ? setFlags ? Arm64Mnemonic.SUBS : Arm64Mnemonic.SUB
            : setFlags ? Arm64Mnemonic.ADDS : Arm64Mnemonic.ADD;
        
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var regD = baseReg + rd;
        var regN = baseReg + rn;
        var regM = baseReg + rm;

        if (shift == Arm64ShiftType.ROR)
            throw new Arm64UndefinedInstructionException("Add/Subtract Shifted Register: Shift type ROR is reserved");

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = shiftAmount == 0 ? Arm64OperandKind.None : Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            Op3Imm = shiftAmount,
            FinalOpShiftType = shiftAmount == 0 ? Arm64ShiftType.NONE : shift,
            MnemonicCategory = Arm64MnemonicCategory.Math
        };
    }
    
    private static Arm64Instruction AddSubtractExtendedRegister(uint instruction)
    {
        var is64Bit = instruction.TestBit(31);
        var isSubtract = instruction.TestBit(30);
        var setFlags = instruction.TestBit(29);
        var opt = (instruction >> 22) & 0b11;
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var extendType = (Arm64ExtendType) ((instruction >> 13) & 0b111);
        var shift = (instruction >> 10) & 0b111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(opt != 0)
            throw new Arm64UndefinedInstructionException("AddSubtractExtendedRegister: opt != 0");
        
        if(shift > 4)
            throw new Arm64UndefinedInstructionException($"AddSubtractExtendedRegister: Shift > 4");
        
        var mnemonic = isSubtract
            ? setFlags ? Arm64Mnemonic.SUBS : Arm64Mnemonic.SUB
            : setFlags ? Arm64Mnemonic.ADDS : Arm64Mnemonic.ADD;
        
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var secondBaseReg = is64Bit
            ? extendType is Arm64ExtendType.UXTX or Arm64ExtendType.SXTX ? Arm64Register.X0 : Arm64Register.W0
            : Arm64Register.W0;

        var regD = baseReg + rd;
        var regN = baseReg + rn;
        var regM = secondBaseReg + rm;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = shift != 0 ? Arm64OperandKind.Immediate : Arm64OperandKind.None,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            Op3Imm = shift,
            FinalOpExtendType = extendType,
            MnemonicCategory = Arm64MnemonicCategory.Math
        };
    }
    
    private static Arm64Instruction AddSubtractWithCarry(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var op = instruction.TestBit(30);
        var sFlag = instruction.TestBit(29);
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        var mnemonic = op 
            ? sFlag ? Arm64Mnemonic.SBCS : Arm64Mnemonic.SBC
            : sFlag ? Arm64Mnemonic.ADCS : Arm64Mnemonic.ADC;
        
        var baseReg = sf ? Arm64Register.X0 : Arm64Register.W0;
        
        var regM = baseReg + rm;
        var regN = baseReg + rn;
        var regD = baseReg + rd;

        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.Math,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
        };
    }
    
    private static Arm64Instruction RotateRightIntoFlags(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var op = instruction.TestBit(30);
        var sFlag = instruction.TestBit(29);
        var imm6 = (instruction >> 15) & 0b11_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var o2 = instruction.TestBit(4);
        var mask = instruction & 0b1111;
        
        if(!sf)
            throw new Arm64UndefinedInstructionException("RotateRightIntoFlags: sf == 0");
        
        if(op)
            throw new Arm64UndefinedInstructionException("RotateRightIntoFlags: op == 1");
        
        if(!sFlag)
            throw new Arm64UndefinedInstructionException("RotateRightIntoFlags: S == 0");
        
        if(o2)
            throw new Arm64UndefinedInstructionException("RotateRightIntoFlags: o2 == 1");
        
        //The ONLY valid encoding is sf, no op, S, no o2, which is RMIF
        //This entire block is FEAT_FlagM stuff but it's trivial to implement so.
        
        var regN = Arm64Register.X0 + rn;
        
        return new()
        {
            Mnemonic = Arm64Mnemonic.RMIF,
            MnemonicCategory = Arm64MnemonicCategory.FlagMath, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Immediate,
            Op2Kind = Arm64OperandKind.Immediate,
            Op0Reg = regN,
            Op1Imm = imm6,
            Op2Imm = mask,
        };
    }
    
    private static Arm64Instruction EvaluateIntoFlags(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var op = instruction.TestBit(30);
        var sFlag = instruction.TestBit(29);
        var opcode2 = (instruction >> 15) & 0b11_1111;
        var sz = instruction.TestBit(14);
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var o3 = instruction.TestBit(4);
        var mask = instruction & 0b1111;
        
        //Only valid encoding is no sf, no op, S set, opcode2 == 0, o3 clear, mask == 0b1101
        //Again this is FEAT_FlagM stuff but trivial to implement
        if(sf)
            throw new Arm64UndefinedInstructionException("EvaluateIntoFlags: sf == 1");
        
        if(op)
            throw new Arm64UndefinedInstructionException("EvaluateIntoFlags: op == 1");
        
        if(!sFlag)
            throw new Arm64UndefinedInstructionException("EvaluateIntoFlags: S == 0");
        
        if(opcode2 != 0)
            throw new Arm64UndefinedInstructionException("EvaluateIntoFlags: opcode2 != 0");
        
        if(o3)
            throw new Arm64UndefinedInstructionException("EvaluateIntoFlags: o3 == 1");
        
        if(mask != 0b1101)
            throw new Arm64UndefinedInstructionException("EvaluateIntoFlags: mask != 0b1101");
        
        var regN = Arm64Register.W0 + rn;
        var mnemonic = sz ? Arm64Mnemonic.SETF16 : Arm64Mnemonic.SETF8;
        
        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.FlagMath,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = regN,
        };
    }

    private static Arm64Instruction ConditionalCompare(uint instruction, bool secondOpIsReg)
    {
        var is64Bit = instruction.TestBit(31);
        var op = instruction.TestBit(30);
        var sFlag = instruction.TestBit(29);
        var imm5 = (instruction >> 16) & 0b1_1111;
        var cond = (Arm64ConditionCode) ((instruction >> 12) & 0b1111);
        var o2 = instruction.TestBit(10);
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var o3 = instruction.TestBit(4);
        var nzcv = instruction & 0b1111;
        
        if(!sFlag)
            throw new Arm64UndefinedInstructionException("ConditionalCompareImmediate: sFlag == 0");
        
        if(o2 || o3)
            throw new Arm64UndefinedInstructionException("ConditionalCompareImmediate: o2 or o3 is set");
        
        var mnemonic = op ? Arm64Mnemonic.CCMP : Arm64Mnemonic.CCMN;
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = secondOpIsReg ? Arm64OperandKind.Register : Arm64OperandKind.Immediate,
            Op2Kind = Arm64OperandKind.Immediate,
            Op0Reg = baseReg + rn,
            Op1Imm = secondOpIsReg ? 0 : imm5,
            Op1Reg = secondOpIsReg ? baseReg + (int)imm5 : Arm64Register.INVALID,
            Op2Imm = nzcv,
            FinalOpConditionCode = cond,
            MnemonicCategory = Arm64MnemonicCategory.Comparison
        };
    }
    
    private static Arm64Instruction ConditionalSelect(uint instruction)
    {
        var is64Bit = instruction.TestBit(31);
        var isInvert = instruction.TestBit(30);
        var setFlags = instruction.TestBit(29);
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var cond = (Arm64ConditionCode) ((instruction >> 12) & 0b1111);
        var op2 = (instruction >> 10) & 0b11;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(setFlags)
            throw new Arm64UndefinedInstructionException("ConditionalSelect: S flag set");
        
        if(op2 > 1)
            throw new Arm64UndefinedInstructionException("ConditionalSelect: op2 > 1");

        var mnemonic = isInvert switch
        {
            false when op2 == 0 => Arm64Mnemonic.CSEL,
            false => Arm64Mnemonic.CSINC,
            true when op2 == 0 => Arm64Mnemonic.CSINV,
            true => Arm64Mnemonic.CSNEG,
        };
        
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        
        var regD = baseReg + rd;
        var regN = baseReg + rn;
        var regM = baseReg + rm;
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = Arm64OperandKind.None,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            FinalOpConditionCode = cond,
            MnemonicCategory = Arm64MnemonicCategory.Comparison,
        };
    }
    
    private static Arm64Instruction DataProcessing3Source(uint instruction)
    {
        var is64Bit = instruction.TestBit(31);
        var op54 = (instruction >> 29) & 0b11;
        var op31 = (instruction >> 21) & 0b111;
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var o0 = instruction.TestBit(15);
        var ra = (int) (instruction >> 10) & 0b1_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(op54 != 0)
            throw new Arm64UndefinedInstructionException("DataProcessing3Source: op54 != 0");

        var mnemonic = op31 switch
        {
            0b000 when o0 => Arm64Mnemonic.MSUB,
            0b000 => Arm64Mnemonic.MADD,
            0b001 when !is64Bit => throw new Arm64UndefinedInstructionException("DataProcessing3Source: op31 == 0b001 && sf == 0"),
            0b001 when o0 =>  Arm64Mnemonic.SMSUBL,
            0b001 => Arm64Mnemonic.SMADDL,
            0b010 when !o0 && is64Bit => Arm64Mnemonic.SMULH,
            0b101 when o0 && is64Bit => Arm64Mnemonic.UMSUBL,
            0b101 when !o0 && is64Bit => Arm64Mnemonic.UMADDL,
            0b110 when o0 && is64Bit => Arm64Mnemonic.UMULH,
            _ => throw new Arm64UndefinedInstructionException($"DataProcessing3Source: unallocated operand combination: op31 = {op31} o0 = {o0} sf = {(is64Bit ? 1 : 0)}")
        };
        
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        
        var regM = baseReg + rm;
        var regN = baseReg + rn;
        var regD = baseReg + rd;
        var regA = baseReg + ra;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = Arm64OperandKind.Register,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            Op3Reg = regA,
            MnemonicCategory = Arm64MnemonicCategory.Math,
        };
    }
}
