﻿namespace Disarm.InternalDisassembly;

internal static class Arm64DataProcessingImmediate
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        //This one, at least, is mercifully simple
        var op0 = (instruction >> 23) & 0b111; //Bits 23-25
        
        //All 8 possible variants are defined, as 7 subcategories.
        return op0 switch
        {
            0b000 or 0b001 => PcRelativeAddressing(instruction),
            0b010 => AddSubtractImmediate(instruction),
            0b011 => AddSubtractImmediateWithTags(instruction),
            0b100 => LogicalImmediate(instruction),
            0b101 => MoveWideImmediate(instruction),
            0b110 => Bitfield(instruction),
            0b111 => Extract(instruction),
            _ => throw new ArgumentOutOfRangeException(nameof(op0), "Impossible op0 value")
        };
    }

    public static Arm64Instruction PcRelativeAddressing(uint instruction)
    {
        var hasP = instruction.TestBit(31);
        var immlo = (instruction >> 29) & 0b11; //01
        var immhi = (instruction >> 5) & 0b111_1111_1111_1111_1111; //Bits 5-23, 000_0000_0100_0011_0011
        var rd = (int) (instruction & 0b11111);
        
        //Signed 21-bit immediate gives 2MB range, result value +/- 1MB
        //If ADRP, concat 12 0s on the end, giving a 33-bit value - 8GB range, +/- 4GB, 4kb aligned
        var immRaw = immhi << 2 | immlo;

        if (hasP)
            immRaw <<= 12;
        
        var imm21 = Arm64CommonUtils.CorrectSignBit(immRaw, hasP ? 33 : 21);

        var mnemonic = hasP ? Arm64Mnemonic.ADRP : Arm64Mnemonic.ADR;

        var regD = Arm64Register.X0 + rd;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Imm = imm21,
            MnemonicCategory = Arm64MnemonicCategory.LoadAddress,
        };
    }

    public static Arm64Instruction AddSubtractImmediate(uint instruction)
    {
        var is64Bit = instruction.TestBit(31); //sf flag
        var isSubtract = instruction.TestBit(30); //op flag
        var setFlags = instruction.TestBit(29); //S flag
        var shiftLeftBy12 = instruction.TestBit(22);

        var imm12 = (ulong) (instruction >> 10) & 0b1111_1111_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(shiftLeftBy12)
            imm12 <<= 12;

        var mnemonic = isSubtract switch
        {
            true when setFlags => Arm64Mnemonic.SUBS,
            true => Arm64Mnemonic.SUB,
            false when setFlags => Arm64Mnemonic.ADDS,
            false => Arm64Mnemonic.ADD
        };

        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;

        var regN = baseReg + rn;
        var regD = baseReg + rd;
        var immediate = is64Bit switch
        {
            true => imm12,
            false => (uint) imm12
        };

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Imm = (long)immediate,
            MnemonicCategory = Arm64MnemonicCategory.Math,
        };
    }

    public static Arm64Instruction AddSubtractImmediateWithTags(uint instruction)
    {
        //Technically this is all MTE extension which isn't really supported, but it's simple enough to disassemble
        var sf = instruction.TestBit(31);
        var s = instruction.TestBit(29);
        var o2 = instruction.TestBit(22);
        
        if(o2)
            throw new Arm64UndefinedInstructionException("Add/subtract immediate (with tags): o2 set");
        
        if(!sf)
            throw new Arm64UndefinedInstructionException("Add/subtract immediate (with tags): sf not set");
        
        if(s)
            throw new Arm64UndefinedInstructionException("Add/subtract immediate (with tags): S set");
        
        var op = instruction.TestBit(30);
        var uimm6 = (instruction >> 16) & 0b11_1111;
        var op3 = (int) (instruction >> 14) & 0b11;
        var uimm4 = (instruction >> 10) & 0b1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        var regN = Arm64Register.X0 + rn;
        var regD = Arm64Register.X0 + rd;

        uimm6 <<= 4; //Multiple of 16
        
        return new()
        {
            Mnemonic = op ? Arm64Mnemonic.SUBG : Arm64Mnemonic.ADDG,
            MnemonicCategory = Arm64MnemonicCategory.Math,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
            Op3Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Imm = uimm6,
            Op3Imm = uimm4,
        };
    }

    public static Arm64Instruction LogicalImmediate(uint instruction)
    {
        var is64Bit = instruction.TestBit(31); //sf flag
        var opc = (instruction >> 29) & 0b11; //bits 29-30
        var n = instruction.TestBit(22);
        var immr = (byte) ((instruction >> 16) & 0b11_1111);
        var imms = (byte) ((instruction >> 10) & 0b11_1111);
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;

        if (!is64Bit && n)
            throw new Arm64UndefinedInstructionException("32-bit instruction with N flag set");

        var mnemonic = opc switch
        {
            0b00 => Arm64Mnemonic.AND,
            0b01 => Arm64Mnemonic.ORR,
            0b10 => Arm64Mnemonic.EOR,
            0b11 => Arm64Mnemonic.ANDS,
            _ => throw new("Impossible opc value")
        };
        
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var regN = baseReg + rn;
        var regD = baseReg + rd;

        var (immediate, _) = Arm64CommonUtils.DecodeBitMasks(n, is64Bit ? 64 : 32, imms, immr, true);
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Imm = immediate,
            MnemonicCategory = Arm64MnemonicCategory.Math,
        };
    }

    public static Arm64Instruction MoveWideImmediate(uint instruction)
    {
        var is64Bit = instruction.TestBit(31);
        var opc = (instruction >> 29) & 0b11;
        var hw = (instruction >> 21) & 0b11;
        var imm16 = (instruction >> 5) & 0b1111_1111_1111_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(opc == 0b01)
            throw new Arm64UndefinedInstructionException("Move wide immediate with opc == 0b01");
        
        if(!is64Bit && hw.TestBit(1))
            throw new Arm64UndefinedInstructionException("Move wide immediate with hw bit 1 and !is64Bit");

        var mnemonic = opc switch
        {
            0b00 => Arm64Mnemonic.MOVN, //Move not
            0b10 => Arm64Mnemonic.MOVZ, //Move zero
            0b11 => Arm64Mnemonic.MOVK,
            _ => throw new("Impossible opc value")
        };

        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        
        var regD = baseReg + rd;
        var shift = (int) hw * 16;
       
        // For MOVK, we store the original immediate and shift info
        // For other instructions, we calculate the shifted value
        long immValue;
        Arm64ShiftType shiftType = Arm64ShiftType.NONE;
        int shiftAmount = 0;
        
        if (mnemonic == Arm64Mnemonic.MOVK && shift > 0)
        {
            // For MOVK, store the original 16-bit immediate
            immValue = (long)imm16;
            shiftType = Arm64ShiftType.LSL;
            shiftAmount = shift;
        }
        else
        {
            // For MOVN and MOVZ, calculate the shifted value
            immValue = (long)imm16 << shift;
            //  If the instruction is 32-bit, we need to mask the immediate value to 32 bits
            if (!is64Bit)
                immValue &= 0xFFFFFFFF;
        }
        
        if (mnemonic==Arm64Mnemonic.MOVZ)
        {
            mnemonic = Arm64Mnemonic.MOV;
        }
       
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Imm = immValue,
            Op1ShiftType = shiftType,
            MemExtendOrShiftAmount = shiftAmount,
            MnemonicCategory = Arm64MnemonicCategory.Move,
        };
    }

    public static Arm64Instruction Bitfield(uint instruction)
    {
        var is64Bit = instruction.TestBit(31);
        var opc = (instruction >> 29) & 0b11;
        var n = instruction.TestBit(22);
        var immr = (byte) ((instruction >> 16) & 0b11_1111);
        var imms = (byte) ((instruction >> 10) & 0b11_1111);
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(opc == 0b11)
            throw new Arm64UndefinedInstructionException("Bitfield with opc == 0b11");
        
        if(is64Bit != n)
            throw new Arm64UndefinedInstructionException("Bitfield with is64Bit != n");

        var mnemonic = opc switch
        {
            0b00 => Arm64Mnemonic.SBFM,
            0b01 => Arm64Mnemonic.BFM,
            0b10 => Arm64Mnemonic.UBFM,
            _ => throw new("Impossible opc")
        };
        
        var baseReg = is64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var regN = baseReg + rn;
        var regD = baseReg + rd;

        // var (wmask, tmask) = Arm64CommonUtils.DecodeBitMasks(n, is64Bit ? 64 : 32, imms, immr, false);

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Immediate,
            Op3Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Imm = immr,
            Op3Imm = imms,
            MnemonicCategory = Arm64MnemonicCategory.Move,
        };
    }

    public static Arm64Instruction Extract(uint instruction)
    {
        var sf = instruction.TestBit(31);
        var op21 = (instruction >> 29) & 0b11;
        var nFlag = instruction.TestBit(22);
        var o0 = instruction.TestBit(21);
        var rm = (int) (instruction >> 16) & 0b1_1111;
        var imms = (instruction >> 10) & 0b11_1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(op21 != 0)
            throw new Arm64UndefinedInstructionException("Extract with op21 != 0");
        
        if(sf != nFlag)
            throw new Arm64UndefinedInstructionException("Extract with sf != N");

        if(o0)
            throw new Arm64UndefinedInstructionException("Extract with o0 == 1");

        if (!sf && imms.TestBit(5))
            throw new Arm64UndefinedInstructionException("Extract: imms top bit can only be set if sf is also set");
        
        //Basically op21 and o0 must be clear, sf must be the same as N, and imms top bit must be clear if sf is clear
        
        var baseReg = sf ? Arm64Register.X0 : Arm64Register.W0;
        var regN = baseReg + rn;
        var regD = baseReg + rd;
        var regM = baseReg + rm;
        
        return new()
        {
            Mnemonic = Arm64Mnemonic.EXTR,
            MnemonicCategory = Arm64MnemonicCategory.Unspecified,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op3Kind = Arm64OperandKind.Immediate,
            Op0Reg = regD,
            Op1Reg = regN,
            Op2Reg = regM,
            Op3Imm = imms,
        };
    }
}
