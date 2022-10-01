namespace Disarm.InternalDisassembly;

internal static class Arm64ExceptionGeneration
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var opc = (instruction >> 21) & 0b11;
        var imm16 = (instruction >> 5) & 0b1111_1111_1111_1111;
        var op2 = (instruction >> 2) & 0b111;
        var ll = instruction & 0b11;

        if (op2 != 0)
            throw new Arm64UndefinedInstructionException("Exception generation: op2 != 0");

        var mnemonic = opc switch
        {
            0b000 when ll == 0b01 => Arm64Mnemonic.SVC,
            0b000 when ll == 0b10 => Arm64Mnemonic.HVC,
            0b000 when ll == 0b11 => Arm64Mnemonic.SMC,
            0b001 when ll == 0b00 => Arm64Mnemonic.BRK,
            0b010 when ll == 0b00 => Arm64Mnemonic.HLT,
            0b011 when ll == 0b00 => Arm64Mnemonic.TCANCEL,
            0b101 when ll == 0b01 => Arm64Mnemonic.DCPS1,
            0b101 when ll == 0b10 => Arm64Mnemonic.DCPS2,
            0b101 when ll == 0b11 => Arm64Mnemonic.DCPS3,
            _ => throw new Arm64UndefinedInstructionException($"Exception generation: invalid opc/ll combination: {opc}/{ll}")
        };
        
        return new()
        {
            Mnemonic = mnemonic,
            MnemonicCategory = Arm64MnemonicCategory.Exception,
            Op0Kind = Arm64OperandKind.Immediate,
            Op0Imm = imm16,
        };
    }
}