namespace Disarm.InternalDisassembly;

internal static class Arm64Hints
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var crm = (instruction >> 8) & 0b1111;
        var op2 = (instruction >> 5) & 0b111;

        if (crm is 0 && op2 is 0)
            return new() { Mnemonic = Arm64Mnemonic.NOP };

        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Hint, 
        };
    }
}
