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
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.System, 
        };
    }

    public static Arm64Instruction RegisterMove(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.System, 
        };
    }

    public static Arm64Instruction WithRegisterArgument(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.System
        };
    }
}