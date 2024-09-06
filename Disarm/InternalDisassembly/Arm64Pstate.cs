namespace Disarm.InternalDisassembly;

internal static class Arm64Pstate
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var rt = instruction & 0b11111; // Bits 0-4
        var op1 = (instruction >> 16) & 0b111; // Bits 16-18

        if (rt != 0b11111 || op1 != 0b000) // UNALLOCATED
            throw new Arm64UndefinedInstructionException($"Arm64Pstate: rt != 0b1111 or op1 != 0b000 (rt: {rt:X}, op1: {op1:X})");

        var op2 = (instruction >> 5) & 0b111; // Bits 5-7

        return op2 switch
        {
            0b000 => new()
            {
                Mnemonic = Arm64Mnemonic.CFINV,
                MnemonicCategory = Arm64MnemonicCategory.Pstate,
            },
            0b001 => new()
            {
                Mnemonic = Arm64Mnemonic.XAFLAG,
                MnemonicCategory = Arm64MnemonicCategory.Pstate,
            },
            0b010 => new()
            {
                Mnemonic = Arm64Mnemonic.AXFLAG,
                MnemonicCategory = Arm64MnemonicCategory.Pstate,
            },
            _ => throw new Arm64UndefinedInstructionException($"Arm64Pstate: op2 > 0b010 (op2: {op2:X})")
        };
    }
}