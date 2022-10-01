namespace Disarm.InternalDisassembly;

internal static class Arm64Barriers
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        //TODO
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Barrier,
        };
    }
}