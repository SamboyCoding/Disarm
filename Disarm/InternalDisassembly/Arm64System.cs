namespace Disarm.InternalDisassembly;

internal static class Arm64System
{
    public static Arm64Instruction WithResult(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.System, 
        };
    }

    public static Arm64Instruction General(uint instruction)
    {
        var l = (instruction >> 21) & 1;
        var op1 = (instruction >> 16) & 0b111; // Bits 16-18
        var CRn = (instruction >> 12) & 0b1111; // Bits 12-15
        var CRm = (instruction >> 8) & 0b1111; // Bits 8-11
        var op2 = (instruction >> 5) & 0b111; // Bits 5-7
        var rt = (int)(instruction & 0b11111); // Bits 0-4

        return l == 1
            ? new() // SYSL <Xt>, #<op1>, <Cn>, <Cm>, #<op2>
            {
                Mnemonic = Arm64Mnemonic.SYSL,
                MnemonicCategory = Arm64MnemonicCategory.System, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Immediate,
                Op2Kind = Arm64OperandKind.Immediate,
                Op3Kind = Arm64OperandKind.Immediate,
                Op4Kind = Arm64OperandKind.Immediate,
                Op0Reg = Arm64Register.X0 + rt,
                Op1Imm = op1,
                Op2Imm = CRn,
                Op3Imm = CRm,
                Op4Imm = op2
            }
            : new() // SYS #<op1>, <Cn>, <Cm>, #<op2>{, <Xt>}
            {
                Mnemonic = Arm64Mnemonic.SYS,
                MnemonicCategory = Arm64MnemonicCategory.System, 
                Op0Kind = Arm64OperandKind.Immediate,
                Op1Kind = Arm64OperandKind.Immediate,
                Op2Kind = Arm64OperandKind.Immediate,
                Op3Kind = Arm64OperandKind.Immediate,
                Op4Kind = Arm64OperandKind.Register,
                Op0Imm = op1,
                Op1Imm = CRn,
                Op2Imm = CRm,
                Op3Imm = op2,
                Op4Reg = Arm64Register.X0 + rt,
            };
    }

    public static Arm64Instruction RegisterMove(uint instruction)
    {
        var l = (instruction >> 21) & 1;
        var op0 = ((instruction >> 19) & 1) + 2;
        var systemregLow = (instruction >> 5) & (1 << 18); // Bits 5-18
        var systemreg = systemregLow | (op0 << 14);
        var rt = (int)(instruction & 0b11111); // Bits 0-4
        
        return l == 0 ? new() // MSR (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>), <Xt>
            {
                Mnemonic = Arm64Mnemonic.MSR,
                MnemonicCategory = Arm64MnemonicCategory.System, 
                Op0Kind = Arm64OperandKind.Immediate, // SystemReg,
                Op1Kind = Arm64OperandKind.Register,
                Op0Imm = systemreg,
                Op1Reg = Arm64Register.X0 + rt
            } 
            : new() // MRS <Xt>, (<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)
            {
                Mnemonic = Arm64Mnemonic.MRS,
                MnemonicCategory = Arm64MnemonicCategory.System, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Immediate, // SystemReg,
                Op0Reg = Arm64Register.X0 + rt,
                Op1Imm = systemreg
            };
    }

    public static Arm64Instruction WithRegisterArgument(uint instruction)
    {
        var CRm = (instruction >> 8) & 0b1111; // Bits 8-11
        if (CRm != 0)
            throw new Arm64UndefinedInstructionException($"Arm64System with register argument: CRm != 0 (CRm: {CRm:X})");

        var op2 = (instruction >> 5) & 0b111;
        var rd = (int)(instruction & 0b11111); // Bits 0-4
        
        return op2 switch
        {
            0b000 => new()
            {
                Mnemonic = Arm64Mnemonic.WFET,
                MnemonicCategory = Arm64MnemonicCategory.System,
                Op0Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rd
            },
            0b001 => new()
            {
                Mnemonic = Arm64Mnemonic.WFIT,
                MnemonicCategory = Arm64MnemonicCategory.System,
                Op0Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rd
            },
            _ => throw new Arm64UndefinedInstructionException($"Arm64System with register argument: op2 > 0b001 (op2: {op2:X})")
        };
    }
}