namespace Disarm.InternalDisassembly;

internal static class Arm64Hints
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var crm = (instruction >> 8) & 0b1111; // Bits 8-11
        var op2 = (instruction >> 5) & 0b111; // Bits 5-7

        return crm switch
        {
            0b0000 when op2 == 0b000 => new()
            {
                Mnemonic = Arm64Mnemonic.NOP,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b001 => new()
            {
                Mnemonic = Arm64Mnemonic.YIELD,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b010 => new()
            {
                Mnemonic = Arm64Mnemonic.WFE,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b011 => new()
            {
                Mnemonic = Arm64Mnemonic.WFI,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b100 => new()
            {
                Mnemonic = Arm64Mnemonic.SEV,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b101 => new()
            {
                Mnemonic = Arm64Mnemonic.SEVL,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b110 => new()
            {
                Mnemonic = Arm64Mnemonic.DGH,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            0b0000 when op2 == 0b111 => new()
            {
                Mnemonic = Arm64Mnemonic.XPACLRI,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
            _ => new()
            {
                Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,  
                MnemonicCategory = Arm64MnemonicCategory.Hint,
            },
        };
    }
}
