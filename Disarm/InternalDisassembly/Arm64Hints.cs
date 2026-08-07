namespace Disarm.InternalDisassembly;

internal static class Arm64Hints
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var crm = (instruction >> 8) & 0b1111; // Bits 8-11
        var op2 = (instruction >> 5) & 0b111; // Bits 5-7
        var hintNum = crm << 3 | op2;

        var mnemonic = hintNum switch
        {
            0b0000_000 => Arm64Mnemonic.NOP,
            0b0000_001 => Arm64Mnemonic.YIELD,
            0b0000_010 => Arm64Mnemonic.WFE,
            0b0000_011 => Arm64Mnemonic.WFI,
            0b0000_100 => Arm64Mnemonic.SEV,
            0b0000_101 => Arm64Mnemonic.SEVL,
            0b0000_110 => Arm64Mnemonic.DGH,
            0b0000_111 => Arm64Mnemonic.XPACLRI, //FEAT_PAUTH
            0b0001_000 => Arm64Mnemonic.PACIA1716,
            0b0001_010 => Arm64Mnemonic.PACIB1716,
            0b0001_100 => Arm64Mnemonic.AUTIA1716,
            0b0001_110 => Arm64Mnemonic.AUTIB1716,
            0b0010_000 => Arm64Mnemonic.ESB,
            0b0010_001 => Arm64Mnemonic.PSB_CSYNC,
            0b0010_010 => Arm64Mnemonic.TSB_CSYNC,
            0b0010_100 => Arm64Mnemonic.CSDB,
            0b0011_000 => Arm64Mnemonic.PACIAZ,
            0b0011_001 => Arm64Mnemonic.PACIASP,
            0b0011_010 => Arm64Mnemonic.PACIBZ,
            0b0011_011 => Arm64Mnemonic.PACIBSP,
            0b0011_100 => Arm64Mnemonic.AUTIAZ,
            0b0011_101 => Arm64Mnemonic.AUTIASP,
            0b0011_110 => Arm64Mnemonic.AUTIBZ,
            0b0011_111 => Arm64Mnemonic.AUTIBSP,
            0b0100_000 => Arm64Mnemonic.BTI,
            0b0100_010 => Arm64Mnemonic.BTI_C,
            0b0100_100 => Arm64Mnemonic.BTI_J,
            0b0100_110 => Arm64Mnemonic.BTI_JC,
            _ => Arm64Mnemonic.HINT, //unallocated hints execute as nops, so just show the number
        };

        if (mnemonic == Arm64Mnemonic.HINT)
            return new()
            {
                Mnemonic = Arm64Mnemonic.HINT,
                Op0Kind = Arm64OperandKind.Immediate,
                Op0Imm = hintNum,
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            };

        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.Hint,
        };
    }
}
