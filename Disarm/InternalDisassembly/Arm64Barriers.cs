namespace Disarm.InternalDisassembly;

internal static class Arm64Barriers
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op2 = (instruction >> 5) & 0b111; //Bits 5-7
        var CRm = (instruction >> 8) & 0b1111; // Bits = 8-11
        
        return op2 switch
        {
            0b001 when (CRm & 0b11) == 0b10 /* Bits 8-9 */ => new()
            {
                Mnemonic = Arm64Mnemonic.DSBWithFEATXS,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = CRm >> 2 // Bits 10-11
            },
            0b010 => new()
            {
                Mnemonic = Arm64Mnemonic.CLREX,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = CRm
            },
            0b100 when CRm != 0 => new()
            {
                Mnemonic = Arm64Mnemonic.DSB,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = CRm
            },
            0b100 when CRm == 0 => new()
            {
                Mnemonic = Arm64Mnemonic.SSBB,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
            },
            0b101 => new()
            {
                Mnemonic = Arm64Mnemonic.DMB,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = CRm
            },
            0b110 => new()
            {
                Mnemonic = Arm64Mnemonic.ISB,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = CRm
            },
            0b111 when CRm == 0 => new()
            {
                Mnemonic = Arm64Mnemonic.SB,
                MnemonicCategory = Arm64MnemonicCategory.Barrier,
            },
            _ => throw new Arm64UndefinedInstructionException($"Impossible op2: {op2:X}")
        };
    }
}