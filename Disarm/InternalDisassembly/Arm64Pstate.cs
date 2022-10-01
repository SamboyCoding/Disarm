namespace Disarm.InternalDisassembly;

internal static class Arm64Pstate
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Pstate,
        };
    }
}